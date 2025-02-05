package proxy

import (
	"bytes"
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

	// Table "wholeip" will contain all objects.
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

// InitRules initializes the nftables configuration in a single table "wholeip".
// It flushes the entire ruleset, then re-creates the table with the desired sets, maps, and chains.
// (If a previous table existed, its set elements are saved and then restored.)
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

	// --- Save existing table "cozy_proxy" if present ---
	var savedPod, savedSvc, savedPodSvc, savedSvcPod []nftables.SetElement
	tables, _ := p.conn.ListTables()
	var existingTable *nftables.Table
	for _, t := range tables {
		if t.Family == nftables.TableFamilyIPv4 && t.Name == "cozy_proxy" {
			existingTable = t
			break
		}
	}
	if existingTable != nil {
		log.Info("Found existing 'wholeip' table; saving set/map elements")
		// Create dummy set objects for lookup.
		dummyPod := &nftables.Set{Table: existingTable, Name: "pod", KeyType: nftables.TypeIPAddr}
		dummySvc := &nftables.Set{Table: existingTable, Name: "svc", KeyType: nftables.TypeIPAddr}
		dummyPodSvc := &nftables.Set{Table: existingTable, Name: "pod_svc", KeyType: nftables.TypeIPAddr, DataType: nftables.TypeIPAddr, IsMap: true}
		dummySvcPod := &nftables.Set{Table: existingTable, Name: "svc_pod", KeyType: nftables.TypeIPAddr, DataType: nftables.TypeIPAddr, IsMap: true}
		if elems, err := p.conn.GetSetElements(dummyPod); err == nil {
			savedPod = elems
		}
		if elems, err := p.conn.GetSetElements(dummySvc); err == nil {
			savedSvc = elems
		}
		if elems, err := p.conn.GetSetElements(dummyPodSvc); err == nil {
			savedPodSvc = elems
		}
		if elems, err := p.conn.GetSetElements(dummySvcPod); err == nil {
			savedSvcPod = elems
		}
	} else {
		log.Info("No existing 'cozy_proxy' table found; starting fresh")
	}

	// Flush the entire ruleset.
	p.conn.FlushRuleset()
	log.Info("Flushed entire ruleset")

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

	// Restore saved elements, if any.
	if len(savedPod) > 0 {
		if err := p.conn.SetAddElements(p.podSet, savedPod); err != nil {
			log.Error(err, "Failed to restore elements to pod set")
			return fmt.Errorf("failed to restore elements to pod set: %v", err)
		}
		log.Info("Restored elements to pod set")
	}
	if len(savedSvc) > 0 {
		if err := p.conn.SetAddElements(p.svcSet, savedSvc); err != nil {
			log.Error(err, "Failed to restore elements to svc set")
			return fmt.Errorf("failed to restore elements to svc set: %v", err)
		}
		log.Info("Restored elements to svc set")
	}
	if len(savedPodSvc) > 0 {
		if err := p.conn.SetAddElements(p.podSvcMap, savedPodSvc); err != nil {
			log.Error(err, "Failed to restore elements to pod_svc map")
			return fmt.Errorf("failed to restore elements to pod_svc map: %v", err)
		}
		log.Info("Restored elements to pod_svc map")
	}
	if len(savedSvcPod) > 0 {
		if err := p.conn.SetAddElements(p.svcPodMap, savedSvcPod); err != nil {
			log.Error(err, "Failed to restore elements to svc_pod map")
			return fmt.Errorf("failed to restore elements to svc_pod map: %v", err)
		}
		log.Info("Restored elements to svc_pod map")
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

// EnsureRules ensures that the mapping for svcIP and podIP exists.
// In the pod_svc map (key: pod IP → svc IP) it checks if the given pod already maps to a svc.
// If the pod is mapped to a different svc, a conflict is detected.
// In the svc_pod map (key: svc IP → pod IP), if an entry exists with a different pod,
// the old mapping is overridden.
// The method also makes sure that the raw sets "pod" and "svc" include the given IPs.
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

	// Check pod_svc map: key=pod IP → value should be svcIP.
	podSvcElems, err := p.conn.GetSetElements(p.podSvcMap)
	if err != nil {
		log.Error(err, "Failed to get pod_svc map elements")
		return fmt.Errorf("failed to get pod_svc map elements: %v", err)
	}
	for _, el := range podSvcElems {
		if bytes.Equal(el.Key, parsedPodIP) {
			if !bytes.Equal(el.Val, parsedSvcIP) {
				log.Error(nil, "Mapping conflict in pod_svc: podIP already mapped to a different svcIP",
					"podIP", podIP, "existingSvcIP", net.IP(el.Val).String())
				return fmt.Errorf("conflict: podIP %s already mapped to a different svcIP", podIP)
			}
			// Mapping already exists.
			goto SvcPodCheck
		}
	}
	// Add mapping {pod → svc} in pod_svc.
	if err := p.conn.SetAddElements(p.podSvcMap, []nftables.SetElement{
		{Key: parsedPodIP, Val: parsedSvcIP},
	}); err != nil {
		log.Error(err, "Failed to add mapping to pod_svc", "podIP", podIP, "svcIP", svcIP)
		return fmt.Errorf("failed to add mapping to pod_svc: %v", err)
	}
	log.Info("Added mapping to pod_svc", "podIP", podIP, "svcIP", svcIP)

SvcPodCheck:
	// Check svc_pod map: key=svc IP → value should be podIP.
	svcPodElems, err := p.conn.GetSetElements(p.svcPodMap)
	if err != nil {
		log.Error(err, "Failed to get svc_pod map elements")
		return fmt.Errorf("failed to get svc_pod map elements: %v", err)
	}
	foundSvc := false
	for _, el := range svcPodElems {
		if bytes.Equal(el.Key, parsedSvcIP) {
			foundSvc = true
			if !bytes.Equal(el.Val, parsedPodIP) {
				log.Info("Overriding svc_pod mapping for svcIP", "svcIP", svcIP, "oldPodIP", net.IP(el.Val).String(), "newPodIP", podIP)
				// Delete the old mapping.
				if err := p.conn.SetDeleteElements(p.svcPodMap, []nftables.SetElement{{Key: parsedSvcIP, Val: el.Val}}); err != nil {
					log.Error(err, "Failed to delete old svc_pod mapping", "svcIP", svcIP, "oldPodIP", net.IP(el.Val).String())
					return fmt.Errorf("failed to delete old svc_pod mapping: %v", err)
				}
				// Add the new mapping.
				if err := p.conn.SetAddElements(p.svcPodMap, []nftables.SetElement{{Key: parsedSvcIP, Val: parsedPodIP}}); err != nil {
					log.Error(err, "Failed to add new svc_pod mapping", "svcIP", svcIP, "podIP", podIP)
					return fmt.Errorf("failed to add new svc_pod mapping: %v", err)
				}
			}
			break
		}
	}
	if !foundSvc {
		if err := p.conn.SetAddElements(p.svcPodMap, []nftables.SetElement{
			{Key: parsedSvcIP, Val: parsedPodIP},
		}); err != nil {
			log.Error(err, "Failed to add mapping to svc_pod", "svcIP", svcIP, "podIP", podIP)
			return fmt.Errorf("failed to add mapping to svc_pod: %v", err)
		}
		log.Info("Added mapping to svc_pod", "svcIP", svcIP, "podIP", podIP)
	}

	// Ensure the raw sets contain the IPs.
	if err := p.conn.SetAddElements(p.podSet, []nftables.SetElement{
		{Key: parsedPodIP},
	}); err != nil {
		log.Error(err, "Failed to add pod IP to pod set", "podIP", podIP)
		return fmt.Errorf("failed to add pod IP to pod set: %v", err)
	}
	if err := p.conn.SetAddElements(p.svcSet, []nftables.SetElement{
		{Key: parsedSvcIP},
	}); err != nil {
		log.Error(err, "Failed to add svc IP to svc set", "svcIP", svcIP)
		return fmt.Errorf("failed to add svc IP to svc set: %v", err)
	}

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

	// Flush all changes.
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit DeleteNAT changes")
		return fmt.Errorf("failed to commit DeleteNAT changes: %v", err)
	}
	log.Info("NAT mapping and raw set elements deleted successfully", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// CleanupRules receives a keepMap (keys: svcIP, values: podIP) and removes all mappings
// and raw set elements not matching an entry in keepMap.
func (p *NFTProxyProcessor) CleanupRules(keepMap map[string]string) error {
	log.Info("Starting InitialCleanup", "keepMap", keepMap)

	// --- Clean the maps ---
	// Delete from pod_svc and svc_pod any mapping that is not in keepMap.
	podSvcElems, err := p.conn.GetSetElements(p.podSvcMap)
	if err != nil {
		log.Error(err, "Failed to get pod_svc elements")
		return fmt.Errorf("failed to get pod_svc elements: %v", err)
	}
	var toDeletePodSvc []nftables.SetElement
	var toDeleteSvcPod []nftables.SetElement
	for _, el := range podSvcElems {
		pod := net.IP(el.Key).String()
		svc := net.IP(el.Val).String()
		if expectedPod, exists := keepMap[svc]; !exists || expectedPod != pod {
			log.Info("Marking mapping for deletion", "svcIP", svc, "podIP", pod)
			toDeletePodSvc = append(toDeletePodSvc, nftables.SetElement{Key: el.Key, Val: el.Val})
			toDeleteSvcPod = append(toDeleteSvcPod, nftables.SetElement{Key: el.Val, Val: el.Key})
		}
	}
	if len(toDeletePodSvc) > 0 {
		if err := p.conn.SetDeleteElements(p.podSvcMap, toDeletePodSvc); err != nil {
			log.Error(err, "Failed to delete pod_svc mappings during cleanup")
			return fmt.Errorf("failed to delete pod_svc mappings: %v", err)
		}
		if err := p.conn.SetDeleteElements(p.svcPodMap, toDeleteSvcPod); err != nil {
			log.Error(err, "Failed to delete svc_pod mappings during cleanup")
			return fmt.Errorf("failed to delete svc_pod mappings: %v", err)
		}
		log.Info("Map cleanup completed successfully")
	} else {
		log.Info("No map entries to cleanup")
	}

	// --- Clean the raw sets ---
	// For the pod set: remove any pod IP not present in any keepMap value.
	podSetElems, err := p.conn.GetSetElements(p.podSet)
	if err != nil {
		log.Error(err, "Failed to get pod set elements")
		return fmt.Errorf("failed to get pod set elements: %v", err)
	}
	var toDeletePods []nftables.SetElement
	for _, el := range podSetElems {
		pod := net.IP(el.Key).String()
		found := false
		for _, keepPod := range keepMap {
			if keepPod == pod {
				found = true
				break
			}
		}
		if !found {
			log.Info("Marking pod IP for deletion from raw set", "podIP", pod)
			toDeletePods = append(toDeletePods, nftables.SetElement{Key: el.Key})
		}
	}
	if len(toDeletePods) > 0 {
		if err := p.conn.SetDeleteElements(p.podSet, toDeletePods); err != nil {
			log.Error(err, "Failed to delete pod IPs from pod set")
			return fmt.Errorf("failed to delete pod IPs: %v", err)
		}
		log.Info("Pod set cleanup completed successfully")
	} else {
		log.Info("No pod IPs to delete from pod set")
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
			log.Error(err, "Failed to delete svc IPs from svc set")
			return fmt.Errorf("failed to delete svc IPs: %v", err)
		}
		log.Info("Svc set cleanup completed successfully")
	} else {
		log.Info("No svc IPs to delete from svc set")
	}

	// Final commit.
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit raw set cleanup changes")
		return fmt.Errorf("failed to commit raw set cleanup changes: %v", err)
	}
	log.Info("InitialCleanup completed successfully")
	return nil
}
