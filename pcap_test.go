package pcap

import (
	"testing"
)

func TestPcap ( t *testing.T ) {
	h, err := OpenOffline("test/pcap_files/Network_Join_Nokia_Mobile.pcap")
	if h == nil {
		t.Fail()
		return
	}
	_ = err
}

