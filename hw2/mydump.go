package main

import (
	"bytes"
	_ "bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	_ "flag"
	"fmt"
	_ "fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/google/gopacket/pcap"
	_ "log"
	"os"
	_ "os"
	"strings"
	_ "strings"
	_ "time"
)

func read(deviceInterface, filePath string) (handle *pcap.Handle, err error) {
	if filePath != "" {
		return pcap.OpenOffline(filePath)
	} else {
		if deviceInterface == "" { // interface is not specified, set as default device interface
			ifs, _ := pcap.FindAllDevs()
			deviceInterface = ifs[0].Name
			fmt.Printf("set default interface as %s\n", deviceInterface)
		}
		return pcap.OpenLive(deviceInterface, int32(65535), true, pcap.BlockForever)
	}
}

func processPackets(pktSource gopacket.PacketSource, keyword string) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var arp layers.ARP
	var tcp layers.TCP
	var udp layers.UDP
	var icmp layers.ICMPv4
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &arp, &tcp, &udp, &icmp, &payload)
	var decoded []gopacket.LayerType

	// handle each captured packet and print the formatted output
	for pkt := range pktSource.Packets() {
		// decode packet by pre-defined protocols
		if err := parser.DecodeLayers(pkt.Data(), &decoded); err != nil {
			continue
		}
		var isIpv4 = false
		var notARP = true
		var protocol = "OTHER"
		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeIPv4:
				isIpv4 = true
			case layers.LayerTypeARP:
				notARP = false
			case layers.LayerTypeTCP:
				protocol = "TCP"
			case layers.LayerTypeUDP:
				protocol = "UDP"
			case layers.LayerTypeICMPv4:
				protocol = "ICMP"
			}
		}
		if !isIpv4 {
			continue
		}
		// filter payload by keyword if specified
		if keyword != "" {
			if !bytes.ContainsAny(eth.Payload, keyword) {
				continue
			}
		}

		timestamp := strings.Replace(pkt.Metadata().Timestamp.UTC().String(), " +0000 UTC", "", -1)
		fmt.Printf("%s %s -> %s type %#x len %d\n", timestamp, eth.SrcMAC, eth.DstMAC, binary.BigEndian.Uint16(eth.Contents[12:14]), len(pkt.Data()))
		if notARP {
			if protocol == "TCP" {
				fmt.Printf("%s:%d -> %s:%d TCP", ip4.SrcIP, int16(tcp.SrcPort), ip4.DstIP, int16(tcp.DstPort))
				printTcpFlag(tcp)
				fmt.Println()
			} else if protocol == "UDP" {
				fmt.Printf("%s:%d -> %s:%d UDP\n", ip4.SrcIP, int16(udp.SrcPort), ip4.DstIP, uint16(udp.DstPort))
			} else {
				fmt.Printf("%s -> %s %s\n", ip4.SrcIP, ip4.DstIP, protocol)
			}
		}
		if len(eth.Payload) > 0 {
			fmt.Println(hex.Dump(eth.Payload))
		}
	}

}

func printTcpFlag(tcp layers.TCP) {
	if tcp.FIN {
		fmt.Print(" FIN")
	}
	if tcp.SYN {
		fmt.Print(" SYN")
	}
	if tcp.RST {
		fmt.Print(" RST")
	}
	if tcp.PSH {
		fmt.Print(" PSH")
	}
	if tcp.ACK {
		fmt.Print(" ACK")
	}
	if tcp.URG {
		fmt.Print(" URG")
	}
	if tcp.ECE {
		fmt.Print(" ECE")
	}
	if tcp.CWR {
		fmt.Print(" CWR")
	}
	if tcp.NS {
		fmt.Print(" NS")
	}
}

func main() {
	// Parsing command lines
	var deviceInterface string
	var filePath string
	var keyword string
	var bpfFilterArr []string
	flag.StringVar(&deviceInterface, "i", "", "Live capture from the network device <interface> (e.g., eth0). If not specified, mydump should automatically select a default interface to listen on. Capture should continue indefinitely until the user terminates the program.")
	flag.StringVar(&filePath, "r", "", "Read packets from <file> in tcpdump format")
	flag.StringVar(&keyword, "s", "", "Keep only packets that contain <string> in their payload (after any BPF filter is applied). You are not required to implement wildcard or regular expression matching. A simple string matching operation should suffice.")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println("<expression> is a BPF filter that specifies which packets will be dumped. If no filter is given, all packets seen on the interface (or contained in the trace) should be dumped. Otherwise, only packets matching <expression> should be dumped.")
	}
	flag.Parse()
	bpfFilterArr = flag.Args()
	fmt.Println(deviceInterface, filePath, keyword, strings.Join(bpfFilterArr, " "))

	// read from a pcap file, or capture live packets
	handle, err := read(deviceInterface, filePath)
	if err != nil {
		panic(err)
	}
	if handle == nil {
		panic(err)
	}

	// set BPF filter if specified
	if flag.NArg() != 0 {
		if err := handle.SetBPFFilter(strings.Join(bpfFilterArr, " ")); err != nil {
			panic(err)
		}
	}
	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	processPackets(*packetSource, keyword)
}
