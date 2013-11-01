package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/miekg/pcap"
)

const (
	TYPE_IP  = 0x0800
	TYPE_ARP = 0x0806
	TYPE_IP6 = 0x86DD

	IP_ICMP = 1
	IP_INIP = 4
	IP_TCP  = 6
	IP_UDP  = 17
)

var (
	device  = flag.String("i", "", "interface")
	snaplen = flag.Int("s", 65535, "snaplen")
	hexdump = flag.Bool("X", false, "hexdump")
)

func main() {
	expr := ""

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [ -i interface ] [ -s snaplen ] [ -X ] [ expression ]\n", os.Args[0])
		os.Exit(1)
	}

	flag.Parse()

	if len(flag.Args()) > 0 {
		expr = flag.Arg(0)
	}

	if *device == "" {
		devs, err := pcap.FindAllDevs()
		if err != "" {
			fmt.Fprintln(os.Stderr, "tcpdump: couldn't find any devices:", err)
		}
		if 0 == len(devs) {
			flag.Usage()
		}
		*device = devs[0].Name
	}

	h, err := pcap.OpenLive(*device, int32(*snaplen), true, 500)
	if h == nil {
		fmt.Fprintf(os.Stderr, "tcpdump:", err)
		return
	}

	if expr != "" {
		fmt.Println("tcpdump: setting filter to", expr)
		ferr := h.SetFilter(expr)
		if ferr != nil {
			fmt.Println("tcpdump:", ferr)
		}
	}

	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r == 0 {
			// timeout, continue
			continue
		}
		pkt.Decode()
		fmt.Println(pkt)
		if *hexdump {
			Hexdump(pkt)
		}

	}
	fmt.Fprintln(os.Stderr, "tcpdump:", h.Geterror())

}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Hexdump(pkt *pcap.Packet) {
	for i := 0; i < len(pkt.Data); i += 16 {
		Dumpline(uint32(i), pkt.Data[i:min(i+16, len(pkt.Data))])
	}
}

func Dumpline(addr uint32, line []byte) {
	fmt.Printf("\t0x%04x: ", int32(addr))
	var i uint16
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if i%2 == 0 {
			fmt.Print(" ")
		}
		fmt.Printf("%02x", line[i])
	}
	for j := i; j <= 16; j++ {
		if j%2 == 0 {
			fmt.Print(" ")
		}
		fmt.Print("  ")
	}
	fmt.Print("  ")
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if line[i] >= 32 && line[i] <= 126 {
			fmt.Println("%c", line[i])
		} else {
			fmt.Print(".")
		}
	}
	fmt.Println()
}
