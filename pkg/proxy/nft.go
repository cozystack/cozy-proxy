package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	ctrl "sigs.k8s.io/controller-runtime"
)

var log = ctrl.Log.WithName("nft-proxy-processor")

// NFTProxyProcessor implements a NATProcessor using nftables.
type NFTProxyProcessor struct {
	conn *nftables.Conn

	// Table "cozy_proxy" will contain all objects.
	table *nftables.Table

	// Sets and maps.
	podSet    *nftables.Set // Set "pod": contains pod IPs.
	svcSet    *nftables.Set // Set "svc": contains service IPs.
	podSvcMap *nftables.Set // Map "pod_svc": maps pod IP → svc IP.
	svcPodMap *nftables.Set // Map "svc_pod": maps svc IP → pod IP.

	// Chains.
	rawPrerouting *nftables.Chain // Chain "raw_prerouting": for notrack rules.
	natOutput     *nftables.Chain // Chain "nat_output": for SNAT rule.
	natPrerouting *nftables.Chain // Chain "nat_prerouting": for DNAT rule.
}

// InitRules initializes the nftables configuration in a single table "cozy_proxy".
// It flushes the entire ruleset, then re-creates the table with the desired sets, maps, and chains.
func (p *NFTProxyProcessor) InitRules() error {
	log.Info("Initializing nftables NAT configuration")

	// Create a new connection if needed.
	if p.conn == nil {
		var err error
		p.conn, err = nftables.New()
		if err != nil {
			log.Error(err, "Could not create nftables connection")
			return fmt.Errorf("could not create nftables connection: %v", err)
		}
		log.Info("Created nftables connection")
	} else {
		log.Info("Using existing nftables connection")
	}

	// --- Create new table "cozy_proxy" ---
	p.table = p.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "cozy_proxy",
	})
	log.Info("Created new table", "table", p.table.Name)

	// --- Create Sets and Maps ---
	// Set "pod": contains pod IP addresses.
	p.podSet = &nftables.Set{
		Table:   p.table,
		Name:    "pod",
		KeyType: nftables.TypeIPAddr,
	}
	if err := p.conn.AddSet(p.podSet, nil); err != nil {
		log.Error(err, "Could not add pod set")
		return fmt.Errorf("could not add pod set: %v", err)
	}
	log.Info("Created pod set", "set", p.podSet.Name)

	// Set "svc": contains service IP addresses.
	p.svcSet = &nftables.Set{
		Table:   p.table,
		Name:    "svc",
		KeyType: nftables.TypeIPAddr,
	}
	if err := p.conn.AddSet(p.svcSet, nil); err != nil {
		log.Error(err, "Could not add svc set")
		return fmt.Errorf("could not add svc set: %v", err)
	}
	log.Info("Created svc set", "set", p.svcSet.Name)

	// Map "pod_svc": maps pod IP → svc IP.
	p.podSvcMap = &nftables.Set{
		Table:    p.table,
		Name:     "pod_svc",
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeIPAddr,
		IsMap:    true,
	}
	if err := p.conn.AddSet(p.podSvcMap, nil); err != nil {
		log.Error(err, "Could not add pod_svc map")
		return fmt.Errorf("could not add pod_svc map: %v", err)
	}
	log.Info("Created pod_svc map", "map", p.podSvcMap.Name)

	// Map "svc_pod": maps svc IP → pod IP.
	p.svcPodMap = &nftables.Set{
		Table:    p.table,
		Name:     "svc_pod",
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeIPAddr,
		IsMap:    true,
	}
	if err := p.conn.AddSet(p.svcPodMap, nil); err != nil {
		log.Error(err, "Could not add svc_pod map")
		return fmt.Errorf("could not add svc_pod map: %v", err)
	}
	log.Info("Created svc_pod map", "map", p.svcPodMap.Name)

	// --- Delete Chains ---
	chains, _ := p.conn.ListChains()
	for _, chain := range chains {
		if chain.Table.Name == p.table.Name {
			p.conn.DelChain(chain)
		}
	}

	// --- Create Chains ---
	// Chain "raw_prerouting": hook prerouting, priority raw.
	p.rawPrerouting = p.conn.AddChain(&nftables.Chain{
		Name:     "raw_prerouting",
		Table:    p.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRaw,
	})
	log.Info("Created raw_prerouting chain", "chain", p.rawPrerouting.Name)

	// Chain "nat_output": hook postrouting, priority (srcnat + 1).
	p.natOutput = p.conn.AddChain(&nftables.Chain{
		Name:     "nat_output",
		Table:    p.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATSource + 1),
	})
	log.Info("Created nat_output chain", "chain", p.natOutput.Name)

	// Chain "nat_prerouting": hook prerouting, priority (dstnat + 1).
	p.natPrerouting = p.conn.AddChain(&nftables.Chain{
		Name:     "nat_prerouting",
		Table:    p.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 1),
	})
	log.Info("Created nat_prerouting chain", "chain", p.natPrerouting.Name)

	// --- Add Rules ---
	// In raw_prerouting: two rules are added in one call.

	// Add rule for source addresses.
	p.conn.AddRule(&nftables.Rule{
		Table: p.table,
		Chain: p.rawPrerouting,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        p.podSet.Name,
				SetID:          p.podSet.ID,
			},
			&expr.Notrack{},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})

	// Add rule for destination addresses.
	p.conn.AddRule(&nftables.Rule{
		Table: p.table,
		Chain: p.rawPrerouting,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        p.svcSet.Name,
				SetID:          p.svcSet.ID,
			},
			&expr.Notrack{},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})
	log.Info("Added rules to raw_prerouting chain")

	// In nat_output: SNAT rule: ip saddr set ip saddr map @pod_svc
	p.conn.AddRule(&nftables.Rule{
		Table: p.table,
		Chain: p.natOutput,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				DestRegister:   1,
				SetName:        p.podSvcMap.Name,
				SetID:          p.podSvcMap.ID,
				IsDestRegSet:   true,
			},
			&expr.Payload{
				OperationType:  expr.PayloadWrite,
				SourceRegister: 1,
				Base:           expr.PayloadBaseNetworkHeader,
				Offset:         12,
				Len:            4,
				CsumType:       expr.CsumTypeInet,
				CsumOffset:     10,
				CsumFlags:      unix.NFT_PAYLOAD_L4CSUM_PSEUDOHDR,
			},
		},
	})
	log.Info("Added SNAT rule to nat_output chain")

	// In nat_prerouting: DNAT rule: ip daddr set ip daddr map @svc_pod
	p.conn.AddRule(&nftables.Rule{
		Table: p.table,
		Chain: p.natPrerouting,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				DestRegister:   1,
				SetName:        p.svcPodMap.Name,
				SetID:          p.svcPodMap.ID,
				IsDestRegSet:   true,
			},
			&expr.Payload{
				OperationType:  expr.PayloadWrite,
				SourceRegister: 1,
				Base:           expr.PayloadBaseNetworkHeader,
				Offset:         16,
				Len:            4,
				CsumType:       expr.CsumTypeInet,
				CsumOffset:     10,
				CsumFlags:      unix.NFT_PAYLOAD_L4CSUM_PSEUDOHDR,
			},
		},
	})
	log.Info("Added DNAT rule to nat_prerouting chain")

	// Commit all changes.
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit initial configuration")
		return fmt.Errorf("failed to commit initial configuration: %v", err)
	}
	log.Info("Initial configuration committed successfully")
	return nil
}

// EnsureRules ensures that a one-to-one mapping exists between svcIP and podIP.
// If a mapping already exists for svcIP with a different podIP,
// the old mapping is removed (from svc_pod, pod_svc, and from the raw pod set)
// before the new mapping is added.
func (p *NFTProxyProcessor) EnsureRules(svcIP, podIP string) error {
	log.Info("Ensuring NAT mapping", "svcIP", svcIP, "podIP", podIP)

	parsedSvcIP := net.ParseIP(svcIP).To4()
	if parsedSvcIP == nil {
		return fmt.Errorf("invalid svcIP: %s", svcIP)
	}
	parsedPodIP := net.ParseIP(podIP).To4()
	if parsedPodIP == nil {
		return fmt.Errorf("invalid podIP: %s", podIP)
	}

	// --- Remove conflicting mapping for svcIP in svc_pod map ---
	// If svcIP already maps to a different pod, remove that mapping and
	// delete the old pod from the raw pod set.
	svcPodElems, err := p.conn.GetSetElements(p.svcPodMap)
	if err != nil {
		log.Error(err, "Failed to get svc_pod map elements")
		return fmt.Errorf("failed to get svc_pod map elements: %v", err)
	}
	for _, el := range svcPodElems {
		if bytes.Equal(el.Key, parsedSvcIP) {
			// Found an existing mapping for svcIP.
			if !bytes.Equal(el.Val, parsedPodIP) {
				oldPodIP := el.Val
				log.Info("Updating mapping for svc", "svcIP", svcIP, "oldPodIP", net.IP(oldPodIP).String(), "newPodIP", podIP)
				// Remove the old mapping from svc_pod.
				if err := p.conn.SetDeleteElements(p.svcPodMap, []nftables.SetElement{{Key: parsedSvcIP, Val: oldPodIP}}); err != nil {
					log.Error(err, "Failed to delete old svc_pod mapping", "svcIP", svcIP, "oldPodIP", net.IP(oldPodIP).String())
					return fmt.Errorf("failed to delete old svc_pod mapping: %v", err)
				}
				// Remove the corresponding mapping from pod_svc.
				if err := p.conn.SetDeleteElements(p.podSvcMap, []nftables.SetElement{{Key: oldPodIP, Val: parsedSvcIP}}); err != nil {
					log.Error(err, "Failed to delete corresponding pod_svc mapping", "oldPodIP", net.IP(oldPodIP).String(), "svcIP", svcIP)
					return fmt.Errorf("failed to delete corresponding pod_svc mapping: %v", err)
				}
				// Remove the old pod IP from the raw pod set.
				if err := p.conn.SetDeleteElements(p.podSet, []nftables.SetElement{{Key: oldPodIP}}); err != nil {
					log.Error(err, "Failed to delete old pod IP from raw pod set", "oldPodIP", net.IP(oldPodIP).String())
					return fmt.Errorf("failed to delete old pod IP from raw pod set: %v", err)
				}
			}
			break // svcIP mapping handled; exit loop.
		}
	}

	// --- Remove conflicting mapping for podIP in pod_svc map ---
	// If podIP already maps to a different svc, remove that mapping and delete the podIP
	// from the raw pod set (since the old mapping is no longer desired).
	podSvcElems, err := p.conn.GetSetElements(p.podSvcMap)
	if err != nil {
		log.Error(err, "Failed to get pod_svc map elements")
		return fmt.Errorf("failed to get pod_svc map elements: %v", err)
	}
	for _, el := range podSvcElems {
		if bytes.Equal(el.Key, parsedPodIP) {
			// Found an existing mapping for podIP.
			if !bytes.Equal(el.Val, parsedSvcIP) {
				log.Info("Updating mapping for pod", "podIP", podIP, "oldSvcIP", net.IP(el.Val).String(), "newSvcIP", svcIP)
				// Remove the old mapping from pod_svc.
				if err := p.conn.SetDeleteElements(p.podSvcMap, []nftables.SetElement{{Key: parsedPodIP, Val: el.Val}}); err != nil {
					log.Error(err, "Failed to delete old pod_svc mapping", "podIP", podIP, "oldSvcIP", net.IP(el.Val).String())
					return fmt.Errorf("failed to delete old pod_svc mapping: %v", err)
				}
				// Remove the corresponding mapping from svc_pod.
				if err := p.conn.SetDeleteElements(p.svcPodMap, []nftables.SetElement{{Key: el.Val, Val: parsedPodIP}}); err != nil {
					log.Error(err, "Failed to delete corresponding svc_pod mapping", "oldSvcIP", net.IP(el.Val).String(), "podIP", podIP)
					return fmt.Errorf("failed to delete corresponding svc_pod mapping: %v", err)
				}
				// Remove the old pod IP from the raw pod set.
				if err := p.conn.SetDeleteElements(p.podSet, []nftables.SetElement{{Key: parsedPodIP}}); err != nil {
					log.Error(err, "Failed to delete outdated pod IP from raw pod set", "podIP", podIP)
					return fmt.Errorf("failed to delete outdated pod IP from raw pod set: %v", err)
				}
			}
			break // podIP mapping handled; exit loop.
		}
	}

	// --- Add the new mapping to both maps ---
	if err := p.conn.SetAddElements(p.podSvcMap, []nftables.SetElement{{Key: parsedPodIP, Val: parsedSvcIP}}); err != nil {
		log.Error(err, "Failed to add mapping to pod_svc", "podIP", podIP, "svcIP", svcIP)
		return fmt.Errorf("failed to add mapping to pod_svc: %v", err)
	}
	if err := p.conn.SetAddElements(p.svcPodMap, []nftables.SetElement{{Key: parsedSvcIP, Val: parsedPodIP}}); err != nil {
		log.Error(err, "Failed to add mapping to svc_pod", "svcIP", svcIP, "podIP", podIP)
		return fmt.Errorf("failed to add mapping to svc_pod: %v", err)
	}
	log.Info("Added mapping", "svcIP", svcIP, "podIP", podIP)

	// --- Update raw sets ---
	// Remove any outdated entries have already been removed in the conflict loops,
	// then ensure the new IPs are present.
	if err := p.conn.SetAddElements(p.podSet, []nftables.SetElement{{Key: parsedPodIP}}); err != nil {
		log.Error(err, "Failed to add pod IP to pod set", "podIP", podIP)
		return fmt.Errorf("failed to add pod IP to pod set: %v", err)
	}
	if err := p.conn.SetAddElements(p.svcSet, []nftables.SetElement{{Key: parsedSvcIP}}); err != nil {
		log.Error(err, "Failed to add svc IP to svc set", "svcIP", svcIP)
		return fmt.Errorf("failed to add svc IP to svc set: %v", err)
	}

	// Commit all changes.
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit EnsureNAT changes")
		return fmt.Errorf("failed to commit EnsureNAT changes: %v", err)
	}
	log.Info("NAT mapping ensured successfully", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// DeleteRules removes the mapping for the given svcIP and podIP from both maps
// and also deletes the corresponding IPs from the raw sets ("pod" and "svc").
// This ensures that the raw_prerouting chain no longer matches these IPs.
func (p *NFTProxyProcessor) DeleteRules(svcIP, podIP string) error {
	log.Info("Deleting NAT mapping", "svcIP", svcIP, "podIP", podIP)

	// Parse svcIP and podIP into IPv4 byte slices.
	parsedSvcIP := net.ParseIP(svcIP).To4()
	if parsedSvcIP == nil {
		return fmt.Errorf("invalid svcIP: %s", svcIP)
	}
	parsedPodIP := net.ParseIP(podIP).To4()
	if parsedPodIP == nil {
		return fmt.Errorf("invalid podIP: %s", podIP)
	}

	// Delete mapping from the "pod_svc" map.
	if err := p.conn.SetDeleteElements(p.podSvcMap, []nftables.SetElement{
		{Key: parsedPodIP, Val: parsedSvcIP},
	}); err != nil {
		log.Error(err, "Failed to delete mapping from pod_svc", "podIP", podIP, "svcIP", svcIP)
		return fmt.Errorf("failed to delete mapping from pod_svc: %v", err)
	}

	// Delete mapping from the "svc_pod" map.
	if err := p.conn.SetDeleteElements(p.svcPodMap, []nftables.SetElement{
		{Key: parsedSvcIP, Val: parsedPodIP},
	}); err != nil {
		log.Error(err, "Failed to delete mapping from svc_pod", "svcIP", svcIP, "podIP", podIP)
		return fmt.Errorf("failed to delete mapping from svc_pod: %v", err)
	}

	// Delete the pod IP from the "pod" set.
	if err := p.conn.SetDeleteElements(p.podSet, []nftables.SetElement{
		{Key: parsedPodIP},
	}); err != nil {
		log.Error(err, "Failed to delete pod IP from pod set", "podIP", podIP)
		return fmt.Errorf("failed to delete pod IP from pod set: %v", err)
	}

	// Delete the svc IP from the "svc" set.
	if err := p.conn.SetDeleteElements(p.svcSet, []nftables.SetElement{
		{Key: parsedSvcIP},
	}); err != nil {
		log.Error(err, "Failed to delete svc IP from svc set", "svcIP", svcIP)
		return fmt.Errorf("failed to delete svc IP from svc set: %v", err)
	}

	// Commit all changes.
	if err := p.conn.Flush(); err != nil {
		// Check if the error is ENOENT (no such file or directory) and ignore it.
		// This may happen if the elements or even the table were already removed.
		if errors.Is(err, unix.ENOENT) {
			log.Info("Ignoring ENOENT error during flush in DeleteRules", "error", err)
		} else {
			log.Error(err, "Failed to commit DeleteNAT changes")
			return fmt.Errorf("failed to commit DeleteNAT changes: %v", err)
		}
	}

	log.Info("NAT mapping and raw set elements deleted successfully", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// CleanupRules receives a keepMap (keys: svcIP, values: podIP) representing the desired state.
// It recovers from an inconsistent state by:
// 1. Removing any mappings in the pod_svc and svc_pod maps that do not match keepMap.
// 2. Adding any missing mappings from keepMap into both maps.
// 3. Cleaning up the raw sets (pod and svc) so that only the desired IPs remain.
func (p *NFTProxyProcessor) CleanupRules(keepMap map[string]string) error {
	log.Info("Starting CleanupRules", "keepMap", keepMap)

	// --- Step 1: Clean up mapping sets ---

	// Retrieve current mappings from the pod_svc map.
	// Note: pod_svc maps pod IP → svc IP.
	podSvcElems, err := p.conn.GetSetElements(p.podSvcMap)
	if err != nil {
		log.Error(err, "Failed to get pod_svc elements")
		return fmt.Errorf("failed to get pod_svc elements: %v", err)
	}

	// Build a current mapping in svc->pod direction (for easy comparison with keepMap)
	currentMapping := make(map[string]string) // key: svc, value: pod
	for _, el := range podSvcElems {
		pod := net.IP(el.Key).String()
		svc := net.IP(el.Val).String()
		currentMapping[svc] = pod
	}

	// Prepare slices for elements to delete from both maps.
	var toDeletePodSvc []nftables.SetElement
	var toDeleteSvcPod []nftables.SetElement

	// For each mapping found in the current configuration, if it does not match the desired state, mark it for deletion.
	for svc, pod := range currentMapping {
		if expectedPod, ok := keepMap[svc]; !ok || expectedPod != pod {
			log.Info("Marking inconsistent mapping for deletion", "svcIP", svc, "podIP", pod)
			// Prepare deletion elements.
			// pod_svc: key = pod, val = svc.
			toDeletePodSvc = append(toDeletePodSvc, nftables.SetElement{
				Key: net.ParseIP(pod).To4(),
				Val: net.ParseIP(svc).To4(),
			})
			// svc_pod: key = svc, val = pod.
			toDeleteSvcPod = append(toDeleteSvcPod, nftables.SetElement{
				Key: net.ParseIP(svc).To4(),
				Val: net.ParseIP(pod).To4(),
			})
		}
	}

	// Delete any inconsistent mappings.
	if len(toDeletePodSvc) > 0 {
		if err := p.conn.SetDeleteElements(p.podSvcMap, toDeletePodSvc); err != nil {
			log.Error(err, "Failed to delete inconsistent mappings from pod_svc")
			return fmt.Errorf("failed to delete inconsistent mappings from pod_svc: %v", err)
		}
		if err := p.conn.SetDeleteElements(p.svcPodMap, toDeleteSvcPod); err != nil {
			log.Error(err, "Failed to delete inconsistent mappings from svc_pod")
			return fmt.Errorf("failed to delete inconsistent mappings from svc_pod: %v", err)
		}
		log.Info("Inconsistent mappings removed from both maps")
	} else {
		log.Info("No inconsistent mappings found in maps")
	}

	// --- Step 2: Add missing mappings from keepMap ---

	// For every desired mapping in keepMap, ensure it exists in both maps.
	for svc, pod := range keepMap {
		// Check if the current mapping for svc exists and matches.
		if existingPod, ok := currentMapping[svc]; !ok || existingPod != pod {
			parsedSvcIP := net.ParseIP(svc).To4()
			parsedPodIP := net.ParseIP(pod).To4()
			if parsedSvcIP == nil || parsedPodIP == nil {
				log.Error(nil, "Invalid IP in keepMap", "svcIP", svc, "podIP", pod)
				continue
			}
			// Add mapping to pod_svc (pod → svc)
			if err := p.conn.SetAddElements(p.podSvcMap, []nftables.SetElement{{Key: parsedPodIP, Val: parsedSvcIP}}); err != nil {
				log.Error(err, "Failed to add missing mapping to pod_svc", "podIP", pod, "svcIP", svc)
				return fmt.Errorf("failed to add missing mapping to pod_svc: %v", err)
			}
			// Add mapping to svc_pod (svc → pod)
			if err := p.conn.SetAddElements(p.svcPodMap, []nftables.SetElement{{Key: parsedSvcIP, Val: parsedPodIP}}); err != nil {
				log.Error(err, "Failed to add missing mapping to svc_pod", "svcIP", svc, "podIP", pod)
				return fmt.Errorf("failed to add missing mapping to svc_pod: %v", err)
			}
			log.Info("Added missing mapping", "svcIP", svc, "podIP", pod)
		}
	}

	// --- Step 3: Clean up raw sets ---

	// For the pod set: remove any pod IP that is not present in any desired mapping (keepMap values).
	podSetElems, err := p.conn.GetSetElements(p.podSet)
	if err != nil {
		log.Error(err, "Failed to get pod set elements")
		return fmt.Errorf("failed to get pod set elements: %v", err)
	}
	var toDeletePods []nftables.SetElement
	// Build a set of desired pod IPs.
	desiredPods := make(map[string]struct{})
	for _, pod := range keepMap {
		desiredPods[pod] = struct{}{}
	}
	for _, el := range podSetElems {
		pod := net.IP(el.Key).String()
		if _, exists := desiredPods[pod]; !exists {
			log.Info("Marking pod IP for deletion from raw pod set", "podIP", pod)
			toDeletePods = append(toDeletePods, nftables.SetElement{Key: el.Key})
		}
	}
	if len(toDeletePods) > 0 {
		if err := p.conn.SetDeleteElements(p.podSet, toDeletePods); err != nil {
			log.Error(err, "Failed to delete extra pod IPs from pod set")
			return fmt.Errorf("failed to delete extra pod IPs from pod set: %v", err)
		}
		log.Info("Extra pod IPs removed from pod set")
	} else {
		log.Info("No extra pod IPs found in pod set")
	}

	// For the svc set: remove any svc IP not present as a key in keepMap.
	svcSetElems, err := p.conn.GetSetElements(p.svcSet)
	if err != nil {
		log.Error(err, "Failed to get svc set elements")
		return fmt.Errorf("failed to get svc set elements: %v", err)
	}
	var toDeleteSvcs []nftables.SetElement
	for _, el := range svcSetElems {
		svc := net.IP(el.Key).String()
		if _, exists := keepMap[svc]; !exists {
			log.Info("Marking svc IP for deletion from svc set", "svcIP", svc)
			toDeleteSvcs = append(toDeleteSvcs, nftables.SetElement{Key: el.Key})
		}
	}
	if len(toDeleteSvcs) > 0 {
		if err := p.conn.SetDeleteElements(p.svcSet, toDeleteSvcs); err != nil {
			log.Error(err, "Failed to delete extra svc IPs from svc set")
			return fmt.Errorf("failed to delete extra svc IPs from svc set: %v", err)
		}
		log.Info("Extra svc IPs removed from svc set")
	} else {
		log.Info("No extra svc IPs found in svc set")
	}

	// --- Step 4: Ensure raw sets include all desired IPs ---

	// For the pod set, add any missing pod IPs.
	for _, pod := range keepMap {
		parsedPodIP := net.ParseIP(pod).To4()
		if err := p.conn.SetAddElements(p.podSet, []nftables.SetElement{{Key: parsedPodIP}}); err != nil {
			log.Error(err, "Failed to add missing pod IP to pod set", "podIP", pod)
			return fmt.Errorf("failed to add missing pod IP to pod set: %v", err)
		}
	}
	// For the svc set, add any missing svc IPs.
	for svc := range keepMap {
		parsedSvcIP := net.ParseIP(svc).To4()
		if err := p.conn.SetAddElements(p.svcSet, []nftables.SetElement{{Key: parsedSvcIP}}); err != nil {
			log.Error(err, "Failed to add missing svc IP to svc set", "svcIP", svc)
			return fmt.Errorf("failed to add missing svc IP to svc set: %v", err)
		}
	}

	// --- Final commit ---
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit cleanup changes")
		return fmt.Errorf("failed to commit cleanup changes: %v", err)
	}
	log.Info("CleanupRules completed successfully")
	return nil
}
