package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxSyntheticHosts = 4096

// DNS has no upstream: guest-controlled query labels must not become an egress
// channel. Only approved HTTP requests cause host-side DNS and socket creation.
// Stable per-host addresses preserve the intended name even without TLS SNI.
// The benchmark range is deliberately blocked by the normal outbound dialer.
// Mappings are bounded and never recycled during a VM's lifetime.
type syntheticDNS struct {
	mu     sync.Mutex
	byName map[string][4]byte
	byIP   map[string]string
}

func newSyntheticDNS() *syntheticDNS {
	return &syntheticDNS{byName: make(map[string][4]byte), byIP: make(map[string]string)}
}

func (d *syntheticDNS) address(host string) ([4]byte, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if addr, ok := d.byName[host]; ok {
		return addr, true
	}
	if len(d.byName) >= maxSyntheticHosts {
		return [4]byte{}, false
	}
	i := len(d.byName) + 1
	addr := [4]byte{198, 18, byte(i >> 8), byte(i)}
	d.byName[host] = addr
	d.byIP[netip.AddrFrom4(addr).String()] = host
	return addr, true
}

func (d *syntheticDNS) hostname(ip string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	host, ok := d.byIP[ip]
	return host, ok
}

func validDNSHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

func (d *syntheticDNS) answer(packet []byte) []byte {
	var query dnsmessage.Message
	if err := query.Unpack(packet); err != nil || query.Response {
		return nil
	}
	reply := dnsmessage.Message{Header: dnsmessage.Header{
		ID: query.ID, Response: true, Authoritative: true,
		RecursionDesired: query.RecursionDesired, RecursionAvailable: true,
	}}
	if query.OpCode != 0 || len(query.Questions) != 1 || len(query.Answers) != 0 || len(query.Authorities) != 0 {
		reply.RCode = dnsmessage.RCodeFormatError
	} else {
		q := query.Questions[0]
		reply.Questions = query.Questions
		host := normalizeDomain(q.Name.String())
		if q.Class != dnsmessage.ClassINET || !validDNSHostname(host) {
			reply.RCode = dnsmessage.RCodeNameError
		} else if q.Type == dnsmessage.TypeA {
			var addr [4]byte
			var ok bool
			if host == "localhost" || strings.HasSuffix(host, ".localhost") {
				addr, ok = [4]byte{127, 0, 0, 1}, true
			} else {
				addr, ok = d.address(host)
			}
			if !ok {
				reply.RCode = dnsmessage.RCodeServerFailure
			} else {
				reply.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 60},
					Body:   &dnsmessage.AResource{A: addr},
				}}
			}
		}
		// AAAA, HTTPS/SVCB, and other types get NOERROR/no data. No IPv6 NIC
		// is exposed, and ECH/HTTP3 discovery must not bypass interception.
	}
	packed, err := reply.Pack()
	if err != nil {
		return nil
	}
	return packed
}

func serveDNSStream(conn net.Conn, dns *syntheticDNS) {
	for {
		_ = conn.SetDeadline(time.Now().Add(networkHeaderTimeout))
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		size := binary.BigEndian.Uint16(prefix[:])
		if size > 4096 {
			return
		}
		packet := make([]byte, size)
		if _, err := io.ReadFull(conn, packet); err != nil {
			return
		}
		reply := dns.answer(packet)
		if reply == nil {
			return
		}
		binary.BigEndian.PutUint16(prefix[:], uint16(len(reply)))
		if _, err := conn.Write(append(prefix[:], reply...)); err != nil {
			return
		}
	}
}
