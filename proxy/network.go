package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// This network exists only inside the datagram transport. It is never attached
// to a host interface, bridge, NAT, or host routing table. Keep guest/network.nix
// in sync with these addresses and the MAC configured by PrivateNetwork.swift.
const (
	gatewayIP             = "192.168.127.1"
	guestIP               = "192.168.127.2"
	gatewayMAC            = "\x02\x00\x00\x00\x00\x01"
	guestMAC              = "\x02\x00\x00\x00\x00\x02"
	networkMTU            = 1500
	maxNetworkConnections = 128
)

type virtualNetwork struct {
	stack     *stack.Stack
	link      *channel.Endpoint
	wire      io.ReadWriteCloser
	dns       *syntheticDNS
	dnsUDP    *gonet.UDPConn
	dnsTCP    *gonet.TCPListener
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closing   bool
	workers   sync.WaitGroup
	slots     chan struct{}
	closeOnce sync.Once
	activity  networkActivity
}

func networkFromFD(fd int) (*virtualNetwork, error) {
	file := os.NewFile(uintptr(fd), "guest-ethernet")
	if file == nil {
		return nil, fmt.Errorf("invalid network fd %d", fd)
	}
	conn, err := net.FileConn(file)
	_ = file.Close() // FileConn owns a duplicate.
	if err != nil {
		return nil, fmt.Errorf("open Ethernet socket: %w", err)
	}
	if conn.LocalAddr().Network() != "unixgram" {
		conn.Close()
		return nil, fmt.Errorf("Ethernet transport must be a connected Unix datagram socket")
	}
	n, err := newVirtualNetwork(conn)
	if err != nil {
		conn.Close()
	}
	return n, err
}

func newVirtualNetwork(wire io.ReadWriteCloser) (*virtualNetwork, error) {
	ctx, cancel := context.WithCancel(context.Background())
	n := &virtualNetwork{
		wire: wire, dns: newSyntheticDNS(), ctx: ctx, cancel: cancel,
		slots: make(chan struct{}, maxNetworkConnections),
		// ethernet.Endpoint subtracts the Ethernet header from the underlying MTU.
		link: channel.New(256, networkMTU+header.EthernetMinimumSize, tcpip.LinkAddress(gatewayMAC)),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		}),
	}
	fail := func(err error) (*virtualNetwork, error) { n.Close(); return nil, err }
	// The forwarder terminates guest TCP; it does NOT dial an upstream socket.
	fwd := tcp.NewForwarder(n.stack, 0, maxNetworkConnections, n.acceptTCP)
	n.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	if err := n.stack.CreateNIC(1, ethernet.New(n.link)); err != nil {
		return fail(errors.New(err.String()))
	}
	if err := n.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(netip.MustParseAddr(gatewayIP).As4()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return fail(errors.New(err.String()))
	}
	// Accept guest connections to arbitrary destination IPs and reply as those
	// IPs, but only over our private NIC. Neither option enables host forwarding.
	if err := n.stack.SetPromiscuousMode(1, true); err != nil {
		return fail(errors.New(err.String()))
	}
	if err := n.stack.SetSpoofing(1, true); err != nil {
		return fail(errors.New(err.String()))
	}
	n.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	addr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(netip.MustParseAddr(gatewayIP).As4()), Port: 53}
	var err error
	n.dnsUDP, err = gonet.DialUDP(n.stack, &addr, nil, ipv4.ProtocolNumber)
	if err != nil {
		return fail(err)
	}
	n.dnsTCP, err = gonet.ListenTCP(n.stack, addr, ipv4.ProtocolNumber)
	if err != nil {
		return fail(err)
	}
	return n, nil
}

// startWorker serializes Add against Close/Wait, including gVisor callbacks.
func (n *virtualNetwork) startWorker(fn func()) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closing {
		return false
	}
	n.workers.Add(1)
	go func() { defer n.workers.Done(); fn() }()
	return true
}

func (n *virtualNetwork) acceptTCP(r *tcp.ForwarderRequest) {
	select {
	case n.slots <- struct{}{}:
	default:
		r.Complete(true)
		return
	}
	if !n.startWorker(func() {
		defer func() { <-n.slots }()
		id := r.ID()
		// No general TCP relay. Existing explicitly approved raw TCP remains on
		// its separate vsock service, including private/VPN database access.
		if id.LocalPort != 443 {
			r.Complete(true)
			return
		}
		targetIP := id.LocalAddress.String()
		host, synthetic := n.dns.hostname(targetIP)
		if !synthetic {
			addr, err := netip.ParseAddr(targetIP)
			if err != nil || !isAllowedDestinationAddr(addr) {
				r.Complete(true)
				return
			}
			host = targetIP
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		r.Complete(false)
		if err != nil {
			return
		}
		conn := gonet.NewTCPConn(&wq, ep)
		defer conn.Close()
		stop := context.AfterFunc(n.ctx, func() { conn.Close() })
		defer stop()
		port := strconv.Itoa(int(id.LocalPort))
		measured := &activityConn{Conn: conn, activity: &n.activity}
		serveTransparentTLS(n.ctx, measured, host, port)
	}) {
		<-n.slots
		r.Complete(true)
	}
}

func (n *virtualNetwork) Run(ctx context.Context) error {
	stop := context.AfterFunc(ctx, n.cancel)
	defer stop()
	defer n.Close()
	// Closing the wire wakes the blocking packet reader on cancellation.
	wake := context.AfterFunc(n.ctx, func() { n.wire.Close() })
	defer wake()
	if controlUnixPath != "" {
		n.startWorker(n.reportActivity)
	}
	n.startWorker(n.serveDNSUDP)
	n.startWorker(n.serveDNSTCP)
	n.startWorker(func() {
		for {
			pkt := n.link.ReadContext(n.ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			err := writeEthernet(n.ctx, n.wire, view.AsSlice())
			view.Release()
			pkt.DecRef()
			if err != nil {
				n.cancel()
				return
			}
		}
	})
	frame := make([]byte, networkMTU+header.EthernetMinimumSize+1)
	for {
		size, err := n.wire.Read(frame)
		if err != nil {
			if n.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read guest Ethernet: %w", err)
		}
		if size < header.EthernetMinimumSize || size > networkMTU+header.EthernetMinimumSize {
			continue
		}
		eth := header.Ethernet(frame[:size])
		if eth.Type() != ipv4.ProtocolNumber && eth.Type() != arp.ProtocolNumber {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), frame[:size]...))})
		n.link.InjectInbound(eth.Type(), pkt)
		pkt.DecRef()
	}
}

func (n *virtualNetwork) Close() {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		n.closing = true
		n.mu.Unlock()
		n.cancel()
		_ = n.wire.Close()
		if n.dnsTCP != nil {
			n.dnsTCP.Close()
		}
		if n.dnsUDP != nil {
			n.dnsUDP.Close()
		}
		n.stack.Close()
		n.link.Close()
		n.workers.Wait()
		n.stack.Wait()
		n.link.Drain()
	})
}

func (n *virtualNetwork) serveDNSUDP() {
	packet := make([]byte, 4096)
	for {
		size, peer, err := n.dnsUDP.ReadFrom(packet)
		if err != nil {
			return
		}
		if reply := n.dns.answer(packet[:size]); reply != nil {
			if _, err := n.dnsUDP.WriteTo(reply, peer); err != nil && n.ctx.Err() == nil {
				log.Printf("DNS reply: %v", err)
			}
		}
	}
}

func (n *virtualNetwork) serveDNSTCP() {
	for {
		conn, err := n.dnsTCP.Accept()
		if err != nil {
			return
		}
		select {
		case n.slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		if !n.startWorker(func() {
			defer func() { <-n.slots }()
			defer conn.Close()
			stop := context.AfterFunc(n.ctx, func() { conn.Close() })
			defer stop()
			serveDNSStream(conn, n.dns)
		}) {
			<-n.slots
			conn.Close()
		}
	}
}

// Darwin can return ENOBUFS for a connected Unix datagram socket when its
// peer's receive queue is full, even with a pollable fd. This is backpressure,
// not a failed link. Retain and retry this one frame; never grow an unbounded
// packet queue or tear down the entire network for transient congestion.
func writeEthernet(ctx context.Context, wire io.Writer, frame []byte) error {
	for {
		n, err := wire.Write(frame)
		if err == nil {
			if n != len(frame) {
				return io.ErrShortWrite
			}
			return nil
		}
		if !errors.Is(err, syscall.ENOBUFS) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

const networkHeaderTimeout = 30 * time.Second
