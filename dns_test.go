package dnssd

import (
	"bytes"
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

// TestRemoveDedupHostnameRecords verifies that remove() suppresses duplicate
// A, AAAA, and NSEC records that arise when multiple services share a hostname
// (e.g. two service instances on the same host).
func TestRemoveDedupHostnameRecords(t *testing.T) {
	ip4 := net.IP{192, 168, 1, 1}
	ip6 := net.ParseIP("fe80::1")

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "myhost.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
		A:   ip4,
	}
	aaaa := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "myhost.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120},
		AAAA: ip6,
	}
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "myhost.local.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 120},
		NextDomain: "myhost.local.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA},
	}

	// Simulate the "known answers" already in the message.
	known := []dns.RR{a, aaaa, nsec}

	// A second service on the same host would add the same records again.
	duplicates := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "myhost.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip4,
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "myhost.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: ip6,
		},
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "myhost.local.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
			NextDomain: "myhost.local.",
			TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA},
		},
	}

	result := remove(known, duplicates)
	if len(result) != 0 {
		t.Errorf("remove() left %d duplicate records: %v", len(result), result)
	}
}

// TestNSECTypeBitMapWireEncoding checks that the NSEC TypeBitMap is encoded
// correctly on the wire as {0, 1, 0x40} for a service with only an A record.
//
// A malformed {0, 0, 0} TypeBitMap (window=0, length=0, no bits) tells
// resolvers "no record types exist here", directly contradicting the A record
// and causing browsers to reject the response.
func TestNSECTypeBitMapWireEncoding(t *testing.T) {
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

	// Set an explicit IPv4 address on eth0 so IPsAtInterface returns it.
	iface := &net.Interface{Name: "eth0", Index: 1}
	sv.ifaceIPs = map[string][]net.IP{
		"eth0": {net.IP{192, 168, 1, 1}},
	}

	nsec := NSEC(SRV(sv), sv, iface)
	if nsec == nil {
		t.Fatal("NSEC is nil")
	}

	// The Go-level TypeBitMap must be []uint16{dns.TypeA}.
	if len(nsec.TypeBitMap) != 1 || nsec.TypeBitMap[0] != dns.TypeA {
		t.Fatalf("TypeBitMap = %v, want [%d (TypeA)]", nsec.TypeBitMap, dns.TypeA)
	}

	// Pack to wire and verify the raw TypeBitMap bytes are {0, 1, 0x40}:
	//   0    = window block 0
	//   1    = 1 bitmap byte follows
	//   0x40 = 0b01000000 = bit 1 set (TypeA = type 1, MSB-first)
	msg := new(dns.Msg)
	msg.Extra = []dns.RR{nsec}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal("Pack error:", err)
	}

	want := []byte{0, 1, 0x40}
	if !bytes.Contains(packed, want) {
		t.Errorf("wire bytes do not contain TypeA bitmap {0, 1, 0x40}; full packet: %v", packed)
	}
}
