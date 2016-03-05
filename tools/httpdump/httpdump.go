package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"github.com/akrennmair/gopcap"
)



var out *bufio.Writer
var errout *bufio.Writer

func main() {
	var device *string = flag.String("i", "", "interface")
	var snaplen *int = flag.Int("s", 65535, "snaplen")
	expr := ""

	out = bufio.NewWriter(os.Stdout)
	errout = bufio.NewWriter(os.Stderr)

	flag.Usage = func() {
		fmt.Fprintf(errout, "usage: %s [ -i interface ] [ -s snaplen ] [ expression ]\n", os.Args[0])
		errout.Flush()
		os.Exit(1)
	}

	flag.Parse()

	if len(flag.Args()) > 0 {
		expr = flag.Arg(0)
	}

	if *device == "" {
		devs, err := pcap.Findalldevs()
		if err != nil {
			fmt.Fprintf(errout, "httpdump: couldn't find any devices: %s\n", err)
		}
		if 0 == len(devs) {
			flag.Usage()
		}
		*device = devs[0].Name
	}

	h, err := pcap.Openlive(*device, int32(*snaplen), true, 0)
	if h == nil {
		fmt.Fprintf(errout, "httpdump: %s\n", err)
		errout.Flush()
		return
	}
	defer h.Close()

	if expr != "" {
		ferr := h.Setfilter(expr)
		if ferr != nil {
			fmt.Fprintf(out, "httpdump: %s\n", ferr)
			out.Flush()
		}
	}

	for pkt := h.Next(); pkt != nil; pkt = h.Next() {
		pkt.Decode()
		HttpRequest(pkt)
	}
}

func HttpRequest(pkt *pcap.Packet) {
	if len(pkt.Payload) < 4 {
		return
	}
	head := string(pkt.Payload[:4])
	if head[:3] == "GET" || head == "POST" {
		out.WriteString("[*] " +  pkt.String())
		out.WriteString("\n[*] Request:\n" +  string(pkt.Payload))
		out.Flush()
	}
	if head == "HTTP" {
		head = string(pkt.Payload)
		index := strings.Index(head, "\r\n\r\n")
		if index > 0 {
			out.WriteString("[*] " +  pkt.String())
			out.WriteString("\n[*] Response:\n" +  head[:index+4])
			out.Flush()
		}

	}

}


