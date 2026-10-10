//go:build linux

package proxy

import (
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

// These tests program a real kernel, in a scratch network namespace, so they
// exercise how nftables actually commits a batch rather than how the code
// assumes it does. They need root and skip otherwise.

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

// initializedProcessor returns a processor whose table is programmed in a
// scratch namespace.
func initializedProcessor(t *testing.T) *NFTProxyProcessor {
	t.Helper()
	ns := scratchNetns(t)
	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	p := &NFTProxyProcessor{conn: conn}
	if err := p.InitRules(); err != nil {
		t.Fatalf("InitRules: %v", err)
	}
	return p
}

func ipElem(key, val string) nftables.SetElement {
	return nftables.SetElement{Key: net.ParseIP(key).To4(), Val: net.ParseIP(val).To4()}
}

func seedMap(t *testing.T, p *NFTProxyProcessor, m *nftables.Set, kv map[string]string) {
	t.Helper()
	var elems []nftables.SetElement
	for k, v := range kv {
		elems = append(elems, ipElem(k, v))
	}
	if err := p.conn.SetAddElements(m, elems); err != nil {
		t.Fatalf("queue %s: %v", m.Name, err)
	}
	if err := p.conn.Flush(); err != nil {
		t.Fatalf("seed %s: %v", m.Name, err)
	}
}

func readMap(t *testing.T, p *NFTProxyProcessor, m *nftables.Set) map[string]string {
	t.Helper()
	elems, err := p.conn.GetSetElements(m)
	if err != nil {
		t.Fatalf("read %s: %v", m.Name, err)
	}
	got := make(map[string]string, len(elems))
	for _, el := range elems {
		got[net.IP(el.Key).String()] = net.IP(el.Val).String()
	}
	return got
}

func assertMap(t *testing.T, p *NFTProxyProcessor, m *nftables.Set, want map[string]string) {
	t.Helper()
	got := readMap(t, p, m)
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", m.Name, got, want)
		return
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", m.Name, got, want)
			return
		}
	}
}

// TestCleanupRulesReconcilesEachMapAgainstItsOwnScope seeds the state a node
// inherits from a build that scoped both maps alike, and checks each map ends
// up holding exactly its own keep set: pod_svc every managed service, svc_pod
// only the backend hosted here.
func TestCleanupRulesReconcilesEachMapAgainstItsOwnScope(t *testing.T) {
	p := initializedProcessor(t)

	const (
		svcLocal, podLocal   = "198.51.100.1", "10.244.0.1" // backend on this node
		svcRemote, podRemote = "198.51.100.2", "10.244.1.2" // backend elsewhere
		svcGone, podGone     = "198.51.100.3", "10.244.1.3" // service deleted
		svcNew, podNew       = "198.51.100.4", "10.244.0.4" // not programmed yet
	)
	seedMap(t, p, p.podSvcMap, map[string]string{
		podLocal: svcLocal, podRemote: svcRemote, podGone: svcGone,
	})
	seedMap(t, p, p.svcPodMap, map[string]string{
		svcLocal: podLocal, svcRemote: podRemote, svcGone: podGone,
	})

	keepEgress := map[string]string{svcLocal: podLocal, svcRemote: podRemote, svcNew: podNew}
	keepIngress := map[string]string{svcLocal: podLocal, svcNew: podNew}
	if err := p.CleanupRules(keepEgress, keepIngress); err != nil {
		t.Fatalf("CleanupRules: %v", err)
	}

	assertMap(t, p, p.podSvcMap, map[string]string{
		podLocal: svcLocal, podRemote: svcRemote, podNew: svcNew,
	})
	assertMap(t, p, p.svcPodMap, map[string]string{
		svcLocal: podLocal, svcNew: podNew,
	})
}

// TestDeleteElementsTolerantSurvivesAMissingElement queues a deletion batch
// in which one element is already gone. The kernel aborts the whole
// transaction on it, so the elements that are present must still be removed
// by the per-element retry, not reported as removed while left in place.
func TestDeleteElementsTolerantSurvivesAMissingElement(t *testing.T) {
	p := initializedProcessor(t)

	seedMap(t, p, p.podSvcMap, map[string]string{
		"10.244.0.1": "198.51.100.1",
		"10.244.0.2": "198.51.100.2",
		"10.244.0.9": "198.51.100.9",
	})

	del := []nftables.SetElement{
		ipElem("10.244.0.1", "198.51.100.1"),
		ipElem("10.244.0.5", "198.51.100.5"), // never there
		ipElem("10.244.0.2", "198.51.100.2"),
	}
	if err := p.deleteElementsTolerant(p.podSvcMap, del, "test"); err != nil {
		t.Fatalf("deleteElementsTolerant: %v", err)
	}

	assertMap(t, p, p.podSvcMap, map[string]string{"10.244.0.9": "198.51.100.9"})
}

// TestDeleteElementsTolerantReportsOtherFailures checks that only ENOENT is
// tolerated: a batch the kernel rejects for another reason must surface.
func TestDeleteElementsTolerantReportsOtherFailures(t *testing.T) {
	p := initializedProcessor(t)

	seedMap(t, p, p.podSvcMap, map[string]string{"10.244.0.1": "198.51.100.1"})

	// A 2-byte key cannot belong to an ipv4_addr map.
	del := []nftables.SetElement{{Key: []byte{10, 244}}}
	if err := p.deleteElementsTolerant(p.podSvcMap, del, "test"); err == nil {
		t.Fatal("deleteElementsTolerant succeeded on a malformed element")
	}

	assertMap(t, p, p.podSvcMap, map[string]string{"10.244.0.1": "198.51.100.1"})
}
