package proxy

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cozystack/cozy-proxy/pkg/l4"
)

// NetlinkConntrack deletes conntrack entries over netlink.
type NetlinkConntrack struct {
	// Handle, when set, is used instead of the default one. Tests use it to
	// work in a scratch network namespace.
	Handle *netlink.Handle
}

// Purge deletes the IPv4 conntrack entries stale selects. The kernel has no
// filter for "translated to this backend", so the table is dumped and matched
// here, which is why the caller only purges when a translation was withdrawn.
func (c *NetlinkConntrack) Purge(stale func(l4.Flow) bool) (uint, error) {
	h := c.Handle
	if h == nil {
		var err error
		if h, err = netlink.NewHandle(unix.NETLINK_NETFILTER); err != nil {
			return 0, fmt.Errorf("could not open a netfilter netlink handle: %w", err)
		}
		defer h.Close()
	}
	n, err := h.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, flowFilter(stale))
	if err != nil {
		return n, fmt.Errorf("conntrack purge: %w", err)
	}
	return n, nil
}

// flowFilter adapts a predicate on l4.Flow to the netlink filter interface.
type flowFilter func(l4.Flow) bool

func (f flowFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	lf, ok := toFlow(flow)
	return ok && f(lf)
}

// toFlow extracts what the purge decision needs: the destination the client
// used, and where the replies come from — the backend, when translated.
func toFlow(f *netlink.ConntrackFlow) (l4.Flow, bool) {
	if f == nil {
		return l4.Flow{}, false
	}
	dst, ok := netip.AddrFromSlice(f.Forward.DstIP)
	if !ok {
		return l4.Flow{}, false
	}
	src, ok := netip.AddrFromSlice(f.Reverse.SrcIP)
	if !ok {
		return l4.Flow{}, false
	}
	return l4.Flow{
		Protocol: f.Forward.Protocol,
		OrigDst:  netip.AddrPortFrom(dst.Unmap(), f.Forward.DstPort),
		ReplySrc: netip.AddrPortFrom(src.Unmap(), f.Reverse.SrcPort),
	}, true
}

// Compile-time assertion that NetlinkConntrack satisfies ConntrackPurger.
var _ ConntrackPurger = (*NetlinkConntrack)(nil)
