package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"strings"
	"time"
)

var (
	ifcName   string // interface name
	traceFile string
	bpfFilter string

	respMap = make(map[uint16]DNSInfo) // key: DNS transaction id
)

type DNSInfo struct {
	txid      uint16
	pktTime   time.Time
	nameIpMap map[string][]string
}

func main() {
	parseCommand()
	handle, _ := read()
	defer handle.Close()
	detect(handle)
}

func parseCommand() {
	flag.StringVar(&ifcName, "i", "", "Listen on network device <interface> (e.g., eth0). If not specified, mydump should automatically select a default interface to listen on.")
	flag.StringVar(&traceFile, "r", "", "Read packets from <tracefile> (tcpdump format)")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println("<expression> is a BPF filter.")
	}
	flag.Parse()
	bpfFilterArr := flag.Args()
	if ifcName == "" { // interface is not specified, set as default device interface
		ifs, _ := pcap.FindAllDevs()
		ifcName = ifs[0].Name
	}
	if flag.NArg() != 0 {
		bpfFilter = strings.Join(bpfFilterArr, " ")
	} else {
		bpfFilter = "udp"
	}
	// fmt.Println("Arguments:", ifcName, hostFile, strings.Join(bpfFilterArr, " "))
}

func read() (handle *pcap.Handle, err error) {
	if traceFile != "" {
		handle, err = pcap.OpenOffline(traceFile)
	} else {
		handle, err = pcap.OpenLive(ifcName, int32(65535), true, pcap.BlockForever)
	}
	if err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(bpfFilter); err != nil {
		panic(err)
	}
	return
}

// Detect by identifying duplicate responses within a short time interval towards the same destination,
// which contain different answers for the same A request.
// detect() watches a handle for incoming DNS responses and loops over them.
func detect(handle *pcap.Handle) {
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case packet = <-in:
			if packet == nil {
				return
			}
			if packet.ApplicationLayer() == nil || packet.ApplicationLayer().LayerType() != layers.LayerTypeDNS {
				continue
			}
			dns := packet.ApplicationLayer().(*layers.DNS)
			if !dns.QR { // we only care about QR=1(response) packets
				break
			}

			txid := dns.ID
			dnsInfo := buildDNSInfo(txid, packet.Metadata().Timestamp, *dns, string(dns.Questions[0].Name))
			if original, ok := respMap[txid]; ok { // txid already exists in response map
				printAlert(original, dnsInfo)
			} else {
				respMap[txid] = dnsInfo
			}
		}
	}
}

func buildDNSInfo(txid uint16, pktTime time.Time, dns layers.DNS, name string) DNSInfo {
	nameIpMap := make(map[string][]string)
	for _, ans := range dns.Answers {
		if ans.Type != layers.DNSTypeA || ans.Class != layers.DNSClassIN {
			continue
		}
		if ipList, ok := nameIpMap[name]; ok {
			ipList = append(ipList, ans.IP.String())
			nameIpMap[name] = ipList
		} else {
			nameIpMap[name] = []string{ans.IP.String()}
		}
	}
	return DNSInfo{txid: txid, pktTime: pktTime, nameIpMap: nameIpMap}
}

// Eg:
// 20210309-15:08:49.205618  DNS poisoning attempt
// TXID 0x5cce Request www.example.com
// Answer1 [List of IP addresses]
// Answer2 [List of IP addresses]
func printAlert(info1 DNSInfo, info2 DNSInfo) {
	for name, ipList1 := range info1.nameIpMap {
		if ipList2, ok := info2.nameIpMap[name]; ok {
			if ipList1[0] != ipList2[0] {
				fmt.Println(fmt.Sprintf("%v DNS POISONING ATTEMPT", info2.pktTime))
				fmt.Println(fmt.Sprintf("TXID: %v Request %v", info1.txid, name))
				fmt.Println(fmt.Sprintf("ANSWER 1: [%s]", ipList1))
				fmt.Println(fmt.Sprintf("ANSWER 2: [%s]", ipList2))
			}
		}
	}
}
