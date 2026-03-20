package dnssd

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// TestNSECForHostnameQueryWithNoAutoDiscoveredIPs reproduces the bug where a
// hostname query (A/AAAA) receives no response on Linux when the query arrives
// on an interface that is not the one holding the service's IP address.
//
// IPsAtInterface falls through to iface.Addrs() when no explicit IPs or
// ifaceIPs are set. If the interface passed in is not the one that holds the
// service IP (e.g. a macvlan, Docker bridge, or secondary NIC), Addrs()
// returns empty, causing NSEC to return nil. The responder then builds an
// empty answer section and silently drops the response.
func TestNSECForHostnameQueryWithNoAutoDiscoveredIPs(t *testing.T) {
	cfg := Config{
		Host:   "myhost",
		Name:   "TestSvc",
		Type:   "_http._tcp",
		Domain: "local",
		Port:   8080,
	}
	sv, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate what happens on Linux when IPsAtInterface auto-discovery
	// finds no IPs for the query interface — no explicit IPs, no ifaceIPs,
	// and the interface object does not correspond to a real system interface
	// so iface.Addrs() returns empty.
	iface := &net.Interface{Name: "eth0"}

	nsec := NSEC(SRV(sv), sv, iface)

	// When the service has no IPs resolved for the interface, NSEC returns
	// nil, leaving hostname queries with no answer and no NSEC record.
	// This causes browser mDNS resolution to fail on Linux multi-NIC setups.
	//
	// Expected: NSEC is non-nil with TypeBitMap indicating at least TypeA,
	// even when interface auto-discovery fails — IPsAtInterface should fall
	// back to the service's globally-announced IPs when the specific query
	// interface has none.
	if nsec == nil {
		t.Fatal("NSEC returned nil for hostname query; hostname responses will be silently dropped on Linux multi-NIC setups")
	}

	found := false
	for _, typ := range nsec.TypeBitMap {
		if typ == dns.TypeA {
			found = true
		}
	}
	if !found {
		t.Errorf("NSEC TypeBitMap %v does not include TypeA", nsec.TypeBitMap)
	}
}
