//go:build linux

package proxy

import (
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	v1 "k8s.io/api/core/v1"

	"github.com/cozystack/cozy-proxy/pkg/l4"
)

// These tests program a real kernel, in a scratch network namespace, and
// compare what `nft list` prints with golden files under testdata/l4. They need
// root and skip otherwise; the golden comparison also needs the nft binary.
//
// Regenerate the golden files with:
//
//	go test ./pkg/proxy -run TestL4 -update
var updateGolden = flag.Bool("update", false, "rewrite the golden files under testdata")

// scratchNetns creates a network namespace that lives as long as the test, so
// nothing here ever touches the host's ruleset.
func scratchNetns(t *testing.T) netns.NsHandle {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a network namespace")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		t.Fatalf("netns.Get: %v", err)
	}
	defer func() { _ = orig.Close() }()
	ns, err := netns.New() // also switches this thread into it
	if err != nil {
		t.Skipf("cannot create a network namespace: %v", err)
	}
	if err := netns.Set(orig); err != nil {
		t.Fatalf("netns.Set: %v", err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	return ns
}

func datapathIn(ns netns.NsHandle) *NFTL4Datapath {
	return &NFTL4Datapath{ConnOptions: []nftables.ConnOption{nftables.WithNetNSFd(int(ns))}}
}

// inNetns runs the command inside ns. The child inherits the namespace of the
// thread that forks it, which is locked into ns for the duration.
func inNetns(t *testing.T, ns netns.NsHandle, name string, args ...string) (string, error) {
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
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func nftBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft binary not available")
	}
	return path
}

func listL4Table(t *testing.T, ns netns.NsHandle) string {
	t.Helper()
	out, err := inNetns(t, ns, nftBinary(t), "list", "table", "ip", L4TableName)
	if err != nil {
		t.Fatalf("nft list table: %v\n%s", err, out)
	}
	return out
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "l4", name+".nft")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file (run with -update to create it): %v", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from the golden file\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func a(s string) netip.Addr { return netip.MustParseAddr(s) }

func pk(vip string, proto v1.Protocol, port uint16) l4.PortKey {
	return l4.PortKey{VIP: a(vip), Protocol: proto, Port: port}
}

func bk(ip string, port uint16) l4.Backend { return l4.Backend{IP: a(ip), Port: port} }

// announcerState is what the announcer of two services programs: one with two
// ports and two local backends, one announced here with no local backend.
var announcerState = l4.State{
	VIPs: []netip.Addr{a("192.0.2.10"), a("192.0.2.20"), a("192.0.2.30")},
	Ports: []l4.PortKey{
		pk("192.0.2.10", v1.ProtocolTCP, 80),
		pk("192.0.2.10", v1.ProtocolTCP, 443),
		pk("192.0.2.20", v1.ProtocolTCP, 5432),
	},
	NodeIPs: []netip.Addr{a("10.200.24.11"), a("10.200.24.12"), a("10.200.24.13")},
	Rules: []l4.Rule{
		{PortKey: pk("192.0.2.10", v1.ProtocolTCP, 80), Service: "tenant-a/ingress",
			Backends: []l4.Backend{bk("10.244.0.10", 8080), bk("10.244.0.11", 8080)}},
		{PortKey: pk("192.0.2.10", v1.ProtocolTCP, 443), Service: "tenant-a/ingress",
			Backends: []l4.Backend{bk("10.244.0.10", 8443), bk("10.244.0.11", 8443)}},
		{PortKey: pk("192.0.2.20", v1.ProtocolTCP, 5432), Service: "tenant-b/postgres"},
	},
}

// guardOnlyState is the same cluster seen from a node that announces nothing:
// it guards every VIP and translates none.
var guardOnlyState = l4.State{
	VIPs:    announcerState.VIPs,
	Ports:   announcerState.Ports,
	NodeIPs: announcerState.NodeIPs,
}

func TestL4SyncGolden(t *testing.T) {
	cases := []struct {
		name  string
		state l4.State
	}{
		{"announcer", announcerState},
		{"guard-only", guardOnlyState},
		{"empty", l4.State{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ns := scratchNetns(t)
			if err := datapathIn(ns).Sync(c.state); err != nil {
				t.Fatalf("Sync: %v", err)
			}
			checkGolden(t, c.name, listL4Table(t, ns))
		})
	}
}

// A sync replaces the table as a whole: nothing from the previous state may
// survive, a backend map in particular.
func TestL4SyncReplacesPreviousState(t *testing.T) {
	ns := scratchNetns(t)
	dp := datapathIn(ns)
	if err := dp.Sync(announcerState); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	if err := dp.Sync(guardOnlyState); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	got := listL4Table(t, ns)
	if strings.Contains(got, "backends-") || strings.Contains(got, "dnat") && strings.Contains(got, "numgen") {
		t.Errorf("state of the first sync survived the second:\n%s", got)
	}
	checkGolden(t, "guard-only", got)
}

// Teardown removes the table, is idempotent, and never touches another table
// — the VM mode's in particular.
func TestL4TeardownLeavesOtherTablesAlone(t *testing.T) {
	ns := scratchNetns(t)
	dp := datapathIn(ns)

	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	conn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "cozy_proxy"})
	if err := conn.Flush(); err != nil {
		t.Fatalf("creating the VM mode's table: %v", err)
	}

	if err := dp.Teardown(); err != nil {
		t.Fatalf("Teardown without a table: %v", err)
	}
	if err := dp.Sync(announcerState); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := dp.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}
	var names []string
	for _, tb := range tables {
		names = append(names, tb.Name)
	}
	if len(names) != 1 || names[0] != "cozy_proxy" {
		t.Errorf("tables after Teardown = %v, want only cozy_proxy", names)
	}
}

// Operators inspect one chain at a time. A chain named after an nft keyword
// ("dnat") cannot be named on the command line without quoting, which is how
// this was found on the lab.
func TestL4ChainsCanBeListedByName(t *testing.T) {
	ns := scratchNetns(t)
	if err := datapathIn(ns).Sync(announcerState); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}
	nft := nftBinary(t)
	for _, ch := range chains {
		if ch.Table.Name != L4TableName {
			continue
		}
		if out, err := inNetns(t, ns, nft, "list", "chain", "ip", L4TableName, ch.Name); err != nil {
			t.Errorf("nft list chain %s: %v\n%s", ch.Name, err, out)
		}
	}
}

// The masquerade of node sources must pick a fully random source port. By
// default the kernel keeps the client's port whenever its own conntrack has
// the tuple free, and on the lab that made the announcer reuse a
// 100.64.0.x:<port> tuple 29 to 50 s after a previous connection, while OVS
// still tracked it: the backend's SYN-ACK was dropped in OVN and the client
// retransmitted, 0.06 to 0.1 % of connections taking over a second.
func TestL4MasqueradeIsFullyRandom(t *testing.T) {
	ns := scratchNetns(t)
	if err := datapathIn(ns).Sync(announcerState); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: L4TableName}
	rules, err := conn.GetRules(table, &nftables.Chain{Name: "masq", Table: table})
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	var masqs []*expr.Masq
	for _, r := range rules {
		for _, e := range r.Exprs {
			if m, ok := e.(*expr.Masq); ok {
				masqs = append(masqs, m)
			}
		}
	}
	if len(masqs) != 1 {
		t.Fatalf("want one masquerade in chain masq, got %d", len(masqs))
	}
	if !masqs[0].FullyRandom {
		t.Errorf("the masquerade keeps the client's source port; want fully-random, got %+v", *masqs[0])
	}
}
