//go:build linux

package proxy

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	v1 "k8s.io/api/core/v1"

	"github.com/cozystack/cozy-proxy/pkg/l4"
)

// These tests send real traffic through the L4 table. Three network
// namespaces stand in for a client, the announcer and the node hosting the
// backends:
//
//	client 10.0.1.2 ──── 10.0.1.1 router 10.0.2.1 ──── 10.0.2.2, 10.0.2.3 server
//	                      (cozy_proxy_l4)
//
// The VIP 192.0.2.10 is not configured anywhere: like a MetalLB L2 VIP that
// Cilium released, it only exists through the table.

const (
	testVIP       = "192.0.2.10"
	backendPort   = 8080
	routerToSrv   = "10.0.2.1"
	clientAddr    = "10.0.1.2"
	backendA      = "10.0.2.2"
	backendB      = "10.0.2.3"
	dialTimeout   = 500 * time.Millisecond
	serverTimeout = 2 * time.Second
)

type topology struct {
	client, router, server netns.NsHandle
}

// doIn runs f on a thread switched into ns. Sockets created by f stay in ns.
func doIn(t *testing.T, ns netns.NsHandle, f func() error) error {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatalf("netns.Get: %v", err)
	}
	defer func() { _ = orig.Close() }()
	if err := netns.Set(ns); err != nil {
		t.Fatalf("netns.Set: %v", err)
	}
	defer func() {
		if err := netns.Set(orig); err != nil {
			panic(err) // the thread must not go back to the pool in ns
		}
	}()
	return f()
}

func must(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func newTopology(t *testing.T) topology {
	t.Helper()
	tp := topology{client: scratchNetns(t), router: scratchNetns(t), server: scratchNetns(t)}

	h := map[netns.NsHandle]*netlink.Handle{}
	for _, ns := range []netns.NsHandle{tp.client, tp.router, tp.server} {
		nh, err := netlink.NewHandleAt(ns)
		must(t, "netlink.NewHandleAt", err)
		t.Cleanup(nh.Close)
		h[ns] = nh
		lo, err := nh.LinkByName("lo")
		must(t, "lo", err)
		must(t, "lo up", nh.LinkSetUp(lo))
	}

	// One veth per side, created in the router and moved into its peer.
	link := func(peerNS netns.NsHandle, routerEnd, peerEnd, routerIP, peerIPs string) {
		must(t, "veth "+routerEnd, h[tp.router].LinkAdd(&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: routerEnd}, PeerName: peerEnd,
		}))
		peer, err := h[tp.router].LinkByName(peerEnd)
		must(t, "peer "+peerEnd, err)
		must(t, "move "+peerEnd, h[tp.router].LinkSetNsFd(peer, int(peerNS)))

		r, err := h[tp.router].LinkByName(routerEnd)
		must(t, "router end", err)
		must(t, "router addr", h[tp.router].AddrAdd(r, mustAddr(t, routerIP+"/24")))
		must(t, "router up", h[tp.router].LinkSetUp(r))

		p, err := h[peerNS].LinkByName(peerEnd)
		must(t, "peer end", err)
		for _, ip := range strings.Split(peerIPs, ",") {
			must(t, "peer addr", h[peerNS].AddrAdd(p, mustAddr(t, ip+"/24")))
		}
		must(t, "peer up", h[peerNS].LinkSetUp(p))
		must(t, "peer default route", h[peerNS].RouteAdd(&netlink.Route{
			LinkIndex: p.Attrs().Index, Gw: net.ParseIP(routerIP),
		}))
	}
	link(tp.client, "rc", "cr", "10.0.1.1", clientAddr)
	link(tp.server, "rs", "sr", routerToSrv, backendA+","+backendB)

	must(t, "ip_forward", doIn(t, tp.router, func() error {
		return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)
	}))
	return tp
}

func mustAddr(t *testing.T, cidr string) *netlink.Addr {
	t.Helper()
	a, err := netlink.ParseAddr(cidr)
	must(t, "ParseAddr "+cidr, err)
	return a
}

// serve answers every connection on the backends with "<remote> <local>", so
// the client learns which backend took it and which source it saw.
func serve(t *testing.T, ns netns.NsHandle) {
	t.Helper()
	var ln net.Listener
	must(t, "listen", doIn(t, ns, func() error {
		var err error
		ln, err = net.Listen("tcp4", "0.0.0.0:8080")
		return err
	}))
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(c.RemoteAddr().String() + " " + c.LocalAddr().String() + "\n"))
			_ = c.Close()
		}
	}()
}

type answer struct {
	seenSource netip.Addr // the client address as the backend saw it
	backend    netip.Addr // the backend that took the connection
}

func dial(t *testing.T, ns netns.NsHandle, addr string) (answer, error) {
	t.Helper()
	var conn net.Conn
	err := doIn(t, ns, func() error {
		var err error
		conn, err = net.DialTimeout("tcp4", addr, dialTimeout)
		return err
	})
	if err != nil {
		return answer{}, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(serverTimeout))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return answer{}, err
	}
	f := strings.Fields(line)
	if len(f) != 2 {
		return answer{}, errors.New("malformed answer " + line)
	}
	return answer{
		seenSource: netip.MustParseAddrPort(f[0]).Addr(),
		backend:    netip.MustParseAddrPort(f[1]).Addr(),
	}, nil
}

// routerState is what the announcer programs for one service with two local
// backends on port 80 -> 8080.
func routerState(nodeIPs ...string) l4.State {
	st := l4.State{
		VIPs:  []netip.Addr{a(testVIP)},
		Ports: []l4.PortKey{pk(testVIP, v1.ProtocolTCP, 80)},
		Rules: []l4.Rule{{
			PortKey:  pk(testVIP, v1.ProtocolTCP, 80),
			Service:  "ns/svc",
			Backends: []l4.Backend{bk(backendA, backendPort), bk(backendB, backendPort)},
		}},
	}
	for _, ip := range nodeIPs {
		st.NodeIPs = append(st.NodeIPs, a(ip))
	}
	return st
}

func TestL4DatapathTranslatesAndBalances(t *testing.T) {
	tp := newTopology(t)
	serve(t, tp.server)
	must(t, "Sync", datapathIn(tp.router).Sync(routerState()))

	seen := map[netip.Addr]bool{}
	for i := 0; i < 2; i++ {
		ans, err := dial(t, tp.client, testVIP+":80")
		if err != nil {
			t.Fatalf("connection %d to the VIP: %v", i, err)
		}
		// A client that is not a node keeps its address: this is what lets an
		// Internet client, or a VM with its public IP, be seen as itself.
		if ans.seenSource != a(clientAddr) {
			t.Errorf("backend saw %s, want the client's own address %s", ans.seenSource, clientAddr)
		}
		seen[ans.backend] = true
	}
	if !seen[a(backendA)] || !seen[a(backendB)] {
		t.Errorf("two connections must reach both backends, got %v", seen)
	}
}

// A client that is a node — a pod masqueraded by its own node — must be
// masqueraded again, so the reply comes back through the announcer.
func TestL4DatapathMasqueradesNodeSources(t *testing.T) {
	tp := newTopology(t)
	serve(t, tp.server)
	must(t, "Sync", datapathIn(tp.router).Sync(routerState(clientAddr)))

	ans, err := dial(t, tp.client, testVIP+":80")
	if err != nil {
		t.Fatalf("connection to the VIP: %v", err)
	}
	if ans.seenSource != a(routerToSrv) {
		t.Errorf("backend saw %s, want the announcer's address %s", ans.seenSource, routerToSrv)
	}
}

// Without the guard, the announcer routes an undeclared port onwards — on a
// real node back to the gateway, which loops it. Here the router has no route
// for the VIP, so an unguarded packet would come back as an ICMP error, and
// the client would fail fast instead of timing out.
func TestL4DatapathGuardDropsUndeclaredPorts(t *testing.T) {
	tp := newTopology(t)
	serve(t, tp.server)
	dp := datapathIn(tp.router)

	_, err := dial(t, tp.client, testVIP+":81")
	if err == nil || isTimeout(err) {
		t.Fatalf("without the table, the router must reject the VIP outright, got %v", err)
	}

	must(t, "Sync", dp.Sync(routerState()))
	_, err = dial(t, tp.client, testVIP+":81")
	if !isTimeout(err) {
		t.Errorf("an undeclared port must be dropped silently, got %v", err)
	}
}

// An announced port with no local backend is dropped as well.
func TestL4DatapathDropsPortWithoutBackend(t *testing.T) {
	tp := newTopology(t)
	serve(t, tp.server)
	st := routerState()
	st.Rules[0].Backends = nil
	must(t, "Sync", datapathIn(tp.router).Sync(st))

	if _, err := dial(t, tp.client, testVIP+":80"); !isTimeout(err) {
		t.Errorf("a port without backend must be dropped, got %v", err)
	}
}

// A TCP backend withdrawn from a frontend that remains keeps its flows, as
// behind kube-proxy, while new connections only reach the remaining backend.
// The flows go once the frontend goes — here, the node no longer announcing
// the VIP.
func TestL4DatapathPurgesTCPFlowsWithTheirFrontend(t *testing.T) {
	tp := newTopology(t)
	serve(t, tp.server)
	dp := datapathIn(tp.router)
	ct := &NetlinkConntrack{Handle: conntrackIn(t, tp.router)}

	prev := routerState()
	must(t, "Sync", dp.Sync(prev))
	for i := 0; i < 2; i++ {
		if _, err := dial(t, tp.client, testVIP+":80"); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
	}

	withdrawn := netip.AddrPortFrom(a(backendB), backendPort)
	flowsTo := func(b netip.AddrPort) int {
		n := 0
		for _, f := range listFlows(t, ct.Handle) {
			if f.ReplySrc == b {
				n++
			}
		}
		return n
	}
	if flowsTo(withdrawn) == 0 {
		t.Fatal("no flow towards the backend about to be withdrawn: the test would prove nothing")
	}

	cur := routerState()
	cur.Rules[0].Backends = []l4.Backend{bk(backendA, backendPort)}
	must(t, "Sync", dp.Sync(cur))
	if n, err := ct.Purge(l4.StaleFlows(&prev, cur)); err != nil || n != 0 {
		t.Fatalf("Purge after a TCP backend withdrawal = %d, %v; want nothing purged", n, err)
	}
	if flowsTo(withdrawn) == 0 {
		t.Error("the withdrawn TCP backend lost its flows; they must end on their own")
	}
	for i := 0; i < 2; i++ {
		ans, err := dial(t, tp.client, testVIP+":80")
		if err != nil {
			t.Fatalf("connection after the withdrawal: %v", err)
		}
		if ans.backend != a(backendA) {
			t.Errorf("connection reached %s, want only %s", ans.backend, backendA)
		}
	}

	unannounced := routerState()
	unannounced.Rules = nil
	must(t, "Sync", dp.Sync(unannounced))
	n, err := ct.Purge(l4.StaleFlows(&cur, unannounced))
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n == 0 {
		t.Error("losing the announcement must purge the translated flows")
	}
	if left := flowsTo(withdrawn) + flowsTo(netip.AddrPortFrom(a(backendA), backendPort)); left != 0 {
		t.Errorf("%d translated flows survived the end of the announcement", left)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// echo serves a line-echo on port 9090 of the backends, keeping each
// connection open until the client closes it.
func echo(t *testing.T, ns netns.NsHandle) {
	t.Helper()
	var ln net.Listener
	must(t, "listen", doIn(t, ns, func() error {
		var err error
		ln, err = net.Listen("tcp4", "0.0.0.0:9090")
		return err
	}))
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if _, err := c.Write([]byte(line)); err != nil {
						return
					}
				}
			}()
		}
	}()
}

// Every sync rebuilds the table, and a restarted instance does the same on its
// first pass. A connection established before must keep flowing: its
// translation lives in conntrack, not in the rules.
func TestL4DatapathResyncKeepsEstablishedConnections(t *testing.T) {
	tp := newTopology(t)
	echo(t, tp.server)
	dp := datapathIn(tp.router)
	st := l4.State{
		VIPs:  []netip.Addr{a(testVIP)},
		Ports: []l4.PortKey{pk(testVIP, v1.ProtocolTCP, 90)},
		Rules: []l4.Rule{{
			PortKey:  pk(testVIP, v1.ProtocolTCP, 90),
			Service:  "ns/echo",
			Backends: []l4.Backend{bk(backendA, 9090)},
		}},
	}
	must(t, "Sync", dp.Sync(st))

	var conn net.Conn
	must(t, "dial", doIn(t, tp.client, func() error {
		var err error
		conn, err = net.DialTimeout("tcp4", testVIP+":90", dialTimeout)
		return err
	}))
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	roundTrip := func(msg string) {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(serverTimeout))
		if _, err := conn.Write([]byte(msg + "\n")); err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
		got, err := r.ReadString('\n')
		if err != nil || got != msg+"\n" {
			t.Fatalf("echo of %q = %q, %v", msg, got, err)
		}
	}

	roundTrip("before")
	for i := 0; i < 3; i++ {
		must(t, "re-Sync", dp.Sync(st))
	}
	roundTrip("after")
}
