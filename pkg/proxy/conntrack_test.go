//go:build linux

package proxy

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/cozystack/cozy-proxy/pkg/l4"
)

// conntrackIn returns a netlink handle working in ns.
func conntrackIn(t *testing.T, ns netns.NsHandle) *netlink.Handle {
	t.Helper()
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatalf("netlink.NewHandleAt: %v", err)
	}
	t.Cleanup(h.Close)
	return h
}

// createFlow adds a TCP entry translated from client -> origDst to
// replySrc -> client, the way a DNAT leaves it.
func createFlow(t *testing.T, h *netlink.Handle, client, origDst, replySrc string) {
	t.Helper()
	c := netip.MustParseAddrPort(client)
	d := netip.MustParseAddrPort(origDst)
	r := netip.MustParseAddrPort(replySrc)
	flow := &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET,
		Forward: netlink.IPTuple{
			Protocol: unix.IPPROTO_TCP,
			SrcIP:    net.IP(c.Addr().AsSlice()), SrcPort: c.Port(),
			DstIP: net.IP(d.Addr().AsSlice()), DstPort: d.Port(),
		},
		Reverse: netlink.IPTuple{
			Protocol: unix.IPPROTO_TCP,
			SrcIP:    net.IP(r.Addr().AsSlice()), SrcPort: r.Port(),
			DstIP: net.IP(c.Addr().AsSlice()), DstPort: c.Port(),
		},
		TimeOut:   300,
		ProtoInfo: &netlink.ProtoInfoTCP{State: 3}, // TCP_CONNTRACK_ESTABLISHED
	}
	if err := h.ConntrackCreate(netlink.ConntrackTable, unix.AF_INET, flow); err != nil {
		t.Fatalf("ConntrackCreate %s -> %s: %v", client, origDst, err)
	}
}

func listFlows(t *testing.T, h *netlink.Handle) []l4.Flow {
	t.Helper()
	flows, err := h.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET)
	if err != nil {
		t.Fatalf("ConntrackTableList: %v", err)
	}
	var out []l4.Flow
	for _, f := range flows {
		if lf, ok := toFlow(f); ok {
			out = append(out, lf)
		}
	}
	return out
}

func TestNetlinkConntrackPurgeDeletesSelectedFlowsOnly(t *testing.T) {
	ns := scratchNetns(t)
	h := conntrackIn(t, ns)

	createFlow(t, h, "198.51.100.7:40001", "192.0.2.10:80", "10.244.0.10:8080")   // backend kept
	createFlow(t, h, "198.51.100.7:40002", "192.0.2.10:80", "10.244.0.11:8080")   // backend gone
	createFlow(t, h, "198.51.100.7:40003", "203.0.113.5:443", "10.244.0.11:8443") // same backend IP, other port

	gone := netip.MustParseAddrPort("10.244.0.11:8080")
	purger := &NetlinkConntrack{Handle: h}
	n, err := purger.Purge(func(f l4.Flow) bool { return f.ReplySrc == gone })
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n != 1 {
		t.Errorf("Purge deleted %d flows, want 1", n)
	}

	left := listFlows(t, h)
	if len(left) != 2 {
		t.Fatalf("flows left = %+v, want 2", left)
	}
	for _, f := range left {
		if f.ReplySrc == gone {
			t.Errorf("the selected flow survived: %+v", f)
		}
	}
}

// The flow handed to the predicate must carry the translation: the original
// destination and the source of the replies.
func TestToFlow(t *testing.T) {
	f := &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET,
		Forward: netlink.IPTuple{Protocol: unix.IPPROTO_TCP,
			SrcIP: net.ParseIP("198.51.100.7"), SrcPort: 40001,
			DstIP: net.ParseIP("192.0.2.10"), DstPort: 80},
		Reverse: netlink.IPTuple{Protocol: unix.IPPROTO_TCP,
			SrcIP: net.ParseIP("10.244.0.10"), SrcPort: 8080,
			DstIP: net.ParseIP("100.64.0.4"), DstPort: 21653},
	}
	got, ok := toFlow(f)
	want := l4.Flow{
		Protocol: unix.IPPROTO_TCP,
		OrigDst:  netip.MustParseAddrPort("192.0.2.10:80"),
		ReplySrc: netip.MustParseAddrPort("10.244.0.10:8080"),
	}
	if !ok || got != want {
		t.Errorf("toFlow = %+v, %v, want %+v", got, ok, want)
	}

	if _, ok := toFlow(&netlink.ConntrackFlow{}); ok {
		t.Error("a flow without addresses must be skipped")
	}
}
