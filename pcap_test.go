package pcap

import (
	"testing"
    "fmt"
    "net"
    "time"
)

func TestPcap(t *testing.T) {
	h, err := OpenOffline("test/pcap_files/Network_Join_Nokia_Mobile.pcap")
	if h == nil {
		t.Fail()
		return
	}
	_ = err
}

type pcapNewHandleFunc func (intf string, filter string, readTo int32) (h *Pcap, err error)

func testPcapHandle(t *testing.T, newHandle pcapNewHandleFunc) {
    port := 54321
    h, err := newHandle("lo", fmt.Sprintf("udp dst port %d", port), 2000)
    if h == nil || err != nil {
        if h != nil {
            h.Close()
        }
        t.Fatalf("Failed to create/init pcap handle err:%s", err)
    }

    num := 5
    go udpSvr(port, num, t)
    go udpClient(port, num, 1 * time.Second, t)

    count := 0
    for pkt := h.Next(); pkt != nil; pkt = h.Next() {
        pkt.Decode()
        t.Logf("Packet:%s len:%d", pkt, len(pkt.Payload))
        count += 1
    }

    if count < 5 {
        t.Fatalf("Capture failed num:%d, total received:%d", num, count)
    } else {
        t.Logf("Successfully captured %d packets", count)
    }
}

func TestPcapCreate(t *testing.T) {
    testPcapHandle(t, pcapCreate)
}

func TestPcapOpenLive(t *testing.T) {
    testPcapHandle(t, pcapOpenLive)
}

func pcapCreate(intf string, filter string, readTo int32) (h *Pcap, err error) {
    h, err = Create("lo")
	if h == nil || err != nil {
		return
	}

	err = h.SetSnapLen(65535)
    if err != nil {
        return
    }

    err = h.SetReadTimeout(readTo)
    if err != nil {
        return
    }

    err = h.SetBufferSize(3 * 1024 * 1024)
    if err != nil {
        return
    }

    err = h.Activate()
	if err != nil {
		return
	}

    err = h.SetFilter(filter)
	if err != nil {
		return
	}

    return
}


func pcapOpenLive(intf string, filter string, readTo int32) (h *Pcap, err error) {
    h, err = OpenLive(intf, 65535, true, readTo)
	if h == nil || err != nil {
		return
	}

	err = h.SetFilter(filter)
	if err != nil {
		return
	}

    return
}

func udpClient(port int, num int, wait time.Duration, t *testing.T) {
    time.Sleep(wait)

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Logf("ERROR Failed to resolve udp addr err:%s", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Logf("ERROR Failed to dial udp port:%d err:%s", port, err)
		return
	}

    t.Logf("Start packets to port:%d", port)

    pkt := []byte("hello")
    for i := 0 ; i < num; i++ {
        if l, err := conn.Write(pkt); err != nil || l != len(pkt) {
		    t.Logf("ERROR Failed to send packet size:%d wlen:%d err:%s", len(pkt), l, err)
        }
    }

    t.Logf("Completed sending packets to port:%d", port)
}

func udpSvr(port int, num int, t *testing.T) {
    addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", port))
    if err != nil {
		t.Logf("ERROR UDP Server: failed to resolve udp addr err:%s", err)
		return
	}

    sock, err := net.ListenUDP("udp", addr)
    if err != nil {
		t.Logf("ERROR UDP Server: failed to listen on port:%d err:%s", port, err)
		return
	}

    buf := make([]byte, 10, 1024)
    for i := 0 ; i < num; i++ {
        _, _, err := sock.ReadFromUDP(buf)
        if err != nil {
            t.Logf("Failed to recv packets on port:%d err:%s", port, err)
        }
    }
}
