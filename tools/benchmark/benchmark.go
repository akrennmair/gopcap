package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/pprof"

	"github.com/akrennmair/gopcap"
)

func main() {
	var device *string = flag.String("i", "", "interface")
	var snaplen *int = flag.Int("s", 65535, "snaplen")
	var count *int = flag.Int("c", 10000, "packet count")
	var decode *bool = flag.Bool("d", false, "If true, decode each packet")
	var cpuprofile *string = flag.String("cpuprofile", "", "filename")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s -c packetcount [ -i interface ] [ -s snaplen ] [ -X ] [ -cpuprofile filename ] expression\n", os.Args[0])
		os.Exit(1)
	}

	flag.Parse()

	var expr string
	if len(flag.Args()) > 0 {
		expr = flag.Arg(0)
	}

	if *device == "" {
		devs, err := pcap.Findalldevs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "benchmark: couldn't find any devices: %s\n", err)
		}
		if 0 == len(devs) {
			flag.Usage()
		}
		*device = devs[0].Name
	}

	h, err := pcap.Openlive(*device, int32(*snaplen), true, 0)
	if h == nil {
		fmt.Fprintf(os.Stderr, "benchmark: %s\n", err)
		return
	}
	defer h.Close()

	if expr != "" {
		ferr := h.Setfilter(expr)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "benchmark: %s\n", ferr)
			return
		}
	}

	if *cpuprofile != "" {
		if out, err := os.Create(*cpuprofile); err == nil {
			pprof.StartCPUProfile(out)
			defer func() {
				pprof.StopCPUProfile()
				out.Close()
			}()
		} else {
			panic(err)
		}
	}

	i := 0
	for pkt := h.Next(); pkt != nil; pkt = h.Next() {
		if *decode {
			pkt.Decode()
		}
		if i++; i >= *count {
			break
		}
	}
}
