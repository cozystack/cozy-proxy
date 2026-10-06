# RFC: L4 LoadBalancer mode

| | |
|---|---|
| Status | Draft. Phase 1 prototype on branch `feat/l4-loadbalancer` (section 11) |
| Scope | cozy-proxy, plus the Cozystack charts that would opt services in |
| Supersedes | nothing; the existing VM mode is unchanged |

## 1. Problem

Cozystack isolates tenants on **egress**: every tenant namespace carries a
`CiliumClusterwideNetworkPolicy` that only lets its pods talk to their own
tenant, a few platform services, and `world`. Ingress policies are wide open to
`world` and `cluster`.

That model has a blind spot for public IPs. When a pod connects to the public
IP of a `LoadBalancer` service handled by Cilium (kube-proxy replacement), Cilium
translates the destination **inside the client pod**, before the egress policy is
evaluated. The egress verdict is then taken against the backend's identity and
the post-translation port. A pod of tenant A connecting to the public IP of
tenant B's Postgres is therefore judged as "A talking to B's pod" and dropped,
although the same connection from the Internet succeeds.

So a tenant cannot reach another tenant's public endpoint (or even a parent
tenant's ingress, for nested projects) by its public IP, which users do
expect: a public IP is public. VM services already behave correctly, because
they are handled by cozy-proxy, which Cilium ignores: the packet leaves the
client pod with the public IP as destination, is evaluated as `world`, leaves the
node and comes back through the normal ingress path.

The other `LoadBalancer` services cannot use cozy-proxy today:

- the ingress of tenant Kubernetes clusters, created on the infra side by the
  kubevirt cloud-controller-manager (CCM);
- tenant `Ingress` applications (ingress-nginx);
- `Postgres` and `MariaDB` with `external: true`.

cozy-proxy's VM mode is a stateless 1:1 NAT: it rewrites addresses without
touching ports, assumes exactly one backend, and only reads `v1.Endpoints`.
These services need port translation (CCM services target the tenant node
ports), several backends, EndpointSlices (CCM services are selector-less and
their slices are written by `kubevirt-eps-controller`), readiness, and a stateful
NAT so that several backends can share one IP.

This RFC proposes a second, independent datapath in cozy-proxy — the **L4 mode**
— that takes such services over from Cilium on the ingress path, so that their
public IP is reachable from every tenant, with the client seen as `world`.

## 2. Model

### 2.1 Retained model (E3)

```
                       MetalLB L2 announcer of the VIP (node N)
 client ──► VIP:port ──► guard ──► DNAT to a *local* ready backend (conntrack)
                                    └─ if the source is a node IP: masquerade
                         ◄────────── un-NAT by conntrack on the reply ◄── backend
```

1. **DNAT, stateful, on the announcer only.** The node MetalLB elected to answer
   ARP for the VIP DNATs new connections to one of its *local* ready backends,
   with port translation. Replies come back through the same node's conntrack,
   which reverses the translation. Services must use
   `externalTrafficPolicy: Local`, which is also what makes MetalLB pick an
   announcer that has a local backend.
2. **Masquerade only sources that are node IPs.** An in-cluster pod reaching the
   VIP from another node is masqueraded by kube-ovn to *its node's* IP before
   leaving that node. If the announcer forwarded that packet unchanged, the
   backend would answer the node IP directly, OVN would tunnel the reply
   straight to the client's node, and that node would see a reply from the pod IP
   to a connection it opened towards the VIP: RST. Masquerading those sources on
   the announcer pins the reply to the announcer. Node IPs are read from the
   `Node` objects (`InternalIP`), so the rule matches exactly the cluster's
   nodes, not a CIDR guess — on some installs the LoadBalancer pool sits in the
   node subnet.
3. **Every other source is preserved**: an Internet client is seen with its own
   IP, a VM client with its public (VM service) IP.
4. **A guard drops everything else addressed to the VIP.** Without it, a packet
   for an undeclared port is not translated, the VIP is not a local address any
   more (Cilium released it), and the announcer forwards it to its default
   gateway, which sends it straight back: a routing loop until the TTL expires.
   This was observed on the lab.

Observed on the lab with this model (3 nodes, kube-ovn + Cilium chaining,
MetalLB L2):

| Client | Result | Source seen by the backend |
|---|---|---|
| pod on the announcer | OK | `100.64.0.x` (kube-ovn join IP), Cilium identity `world` |
| pod on another node | OK | `100.64.0.x` of the announcer, identity `world` |
| VM on another node (cozy-proxy VM service) | OK | the VM's public IP |
| Internet | OK | the client's real IP |

### 2.2 Rejected: DNAT on the announcer without masquerade (E1)

Works for the Internet and for pods on the announcer. A pod on another node gets
a RST: its node masquerades it to the node IP, the backend answers that node IP,
and OVN carries the SYN-ACK in Geneve directly to the client's node without
going back through the announcer's conntrack. Capture on the client node:

```
ovn0        In  10.246.4.189.60638 > VIP.80        [S]
bond0.324   Out 10.200.24.12.45576 > VIP.80        [S]
genev_sys   P   10.246.4.186.8080  > 10.200.24.12.45576 [S.]   <- straight from the pod
ovn0        Out 10.200.24.12.45576 > 10.246.4.186.8080  [R]
```

### 2.3 Rejected: DNAT on every node plus masquerade (E2)

DNAT on every node, masquerading everything that enters from the pod interface,
fixes pod clients and breaks VM clients. A VM's egress is rewritten by
cozy-proxy's VM mode at priority `raw`, before conntrack (`egress_snat`). With a
DNAT and a masquerade on the VM's own node, the reply is de-masqueraded by
conntrack only after the VM mode's stateless `ingress_dnat` (priority `mangle`)
has already run, so the destination is never turned back into the VM's pod IP,
and the VM mode's `port_filter` drops the packet as a new flow on an
undeclared port.

### 2.4 How Cilium is told to let go

The service carries the annotation

```yaml
service.cilium.io/type: ClusterIP
```

Cilium then installs only the ClusterIP frontend: it no longer translates the
VIP (nor the NodePort), while in-cluster traffic to the ClusterIP keeps its
current, isolated behavior. MetalLB still allocates and announces the VIP.
Verified on the lab.

`service.kubernetes.io/service-proxy-name` is **not** used for this mode: it
makes Cilium drop the ClusterIP and the NodePort as well.

### 2.5 How cozy-proxy recognizes the service

A label distinct from the VM mode's:

```yaml
metadata:
  labels:
    networking.cozystack.io/lb-proxy: cozy-proxy
  annotations:
    service.cilium.io/type: ClusterIP
```

| Label | Annotation | cozy-proxy L4 mode |
|---|---|---|
| absent | any | ignores the service |
| present | absent or another value | ignores it and logs: Cilium still owns the VIP, two owners would race |
| present | `ClusterIP` | manages the service (if supported, see 2.6) |
| present, and `service-proxy-name: cozy-proxy` | any | ignores it: the VM mode owns the service |

The label is the trust anchor. The annotation alone is not: the kubevirt CCM
copies the tenant Service's annotations onto the infra Service, so a tenant can
set `service.cilium.io/*` annotations on infra objects, but it cannot set labels
there.

### 2.6 Supported services, by phase

| | Phase 1 (MVP) | Later |
|---|---|---|
| Protocol | TCP | UDP |
| `externalTrafficPolicy` | `Local` | `Cluster` (see 6) |
| Address family | IPv4 | IPv6 |
| Ports / backends | many / many | |
| Endpoints | EndpointSlices, ready, local | terminating fallback |
| Announcer source | MetalLB L2 `ServiceL2Status` | BGP, other LB providers |

A labelled and annotated service that is not supported (for example
`externalTrafficPolicy: Cluster`) is **not** programmed, but its VIP is still
added to the guard, so its traffic is dropped instead of looping. A port the
phase does not support (UDP) is likewise left out of the declared ports, so the
guard drops it.

## 3. Datapath

### 3.1 Table

The L4 mode lives in its own table, `ip cozy_proxy_l4`. It never touches the VM
mode's table `ip cozy_proxy`, and deleting it (`nft delete table ip
cozy_proxy_l4`) removes the L4 mode entirely.

```
table ip cozy_proxy_l4 {
	# Every VIP of a labelled+annotated service, on every node.
	set vips { type ipv4_addr }
	# (VIP, protocol, port) of every supported service port, on every node.
	set vip_ports { type ipv4_addr . inet_proto . inet_service }
	# InternalIP of every Node.
	set node_ips { type ipv4_addr }
	# (backend IP, protocol, backend port) of every local target, announcer only.
	set backends { type ipv4_addr . inet_proto . inet_service }
	# One map per announced frontend: round-robin slot -> backend, commented
	# with the service's namespace/name. nft lists the key type as "type 0"
	# (see addBackendMap).
	map backends-<VIP>-tcp-<port> { type integer : ipv4_addr . inet_service }

	chain guard {
		type filter hook prerouting priority mangle + 10; policy accept;
		ct state established,related accept
		ip daddr @vips ip daddr . meta l4proto . th dport != @vip_ports drop
	}

	chain translate {
		type nat hook prerouting priority dstnat - 5; policy accept;
		# announcer only, one rule per (VIP, port)
		ip daddr <VIP> tcp dport <port> dnat ip to numgen inc mod <n> map @backends-<VIP>-tcp-<port>
		# announcer with no ready local backend for that port
		ip daddr <VIP> tcp dport <port> drop
	}

	chain masq {
		type nat hook postrouting priority srcnat - 5; policy accept;
		ct status dnat ip saddr @node_ips ip daddr . meta l4proto . th dport @backends masquerade fully-random
	}
}
```

Notes:

- `guard` is installed on every node. It accepts `established,related` first, so
  ICMP errors about a translated flow (PMTU) still reach the NAT and are
  translated with it. New packets to a VIP on an undeclared (VIP, protocol,
  port) are dropped, which includes ICMP echo: nobody would answer it anyway.
- `translate` only holds rules on the announcer. Elsewhere the packet is left alone
  and routed out, to the announcer.
- `masq` only matches flows this node translated (`ct status dnat`) towards one
  of its L4 targets, from a node IP, so a node process talking to a backend pod
  directly (a kubelet probe) keeps its source. The masquerade picks the address
  of the interface towards the backend, `ovn0` on kube-ovn, hence the
  `100.64.0.x` source. nft itself would match `ct original ip daddr @vips`;
  `github.com/google/nftables` can only emit that with the generic conntrack
  key, which makes `nft list` abort on the whole ruleset, hence the match on the
  translated destination.
- `nft list` shows the backend maps as `type 0 : ipv4_addr . inet_service`: nft
  only names an integer key through a `typeof` annotation, which
  `github.com/google/nftables` cannot write. The elements are listed correctly
  and the kernel does not look at either.
- `numgen inc` is per node and per rule, which is enough: only one node
  translates a given VIP.

### 3.2 Priorities, and how they interleave with the VM mode

| Priority | Hook | Table | Chain | Effect |
|---|---|---|---|---|
| -300 (raw) | prerouting | `cozy_proxy` | `egress_snat` | VM mode: stateless source rewrite pod IP -> VM VIP, before conntrack |
| -200 | prerouting | | conntrack | flow lookup / creation |
| -150 (mangle) | prerouting | `cozy_proxy` | `ingress_dnat` | VM mode: stateless destination rewrite VM VIP -> pod IP |
| -140 | prerouting | `cozy_proxy_l4` | `guard` | L4: drop undeclared traffic to L4 VIPs |
| -105 | prerouting | `cozy_proxy_l4` | `translate` | L4: stateful DNAT, first packet only |
| -100 | prerouting | | kube-ovn / iptables nat | unchanged |
| 0 (filter) | prerouting | `cozy_proxy` | `port_filter` | VM mode: per-port filter on VM pod IPs |
| 95 | postrouting | `cozy_proxy_l4` | `masq` | L4: masquerade node sources |

The two modes act on disjoint destination addresses (VM VIPs vs L4 VIPs), so
they do not see each other's packets, with one exception: a VM client of an L4
service. Its packet leaves its node with the VM's VIP as source (rewritten at
`raw`, before conntrack), is not masqueraded by the announcer (not a node IP),
and the reply comes back to the VM's node as an ordinary packet to the VM VIP.
That is the lab-validated path.

The opposite case is **not** supported: an L4 backend that is itself the pod of
a VM-mode service. Its replies would be source-rewritten at `raw` before
conntrack, so the reverse translation could not match, and the VM mode's
`port_filter` would see the L4 DNAT as a new flow. The L4 mode excludes such
backends and logs it.

### 3.3 Programming model

The L4 table is small (tens of services) and is **rebuilt as a whole** on every
change, in one netlink transaction:

```
add table ip cozy_proxy_l4      # so that the delete below cannot fail
delete table ip cozy_proxy_l4
add table ip cozy_proxy_l4 { ...full desired state... }
```

nftables applies a batch atomically: a packet sees either the old or the new
ruleset, never a mix, and conntrack entries are not affected by rule changes.
There is no incremental diff to get wrong, no stale element to garbage-collect,
and a retry is simply the next full sync. This deliberately differs from the VM
mode, whose per-element updates needed the series of fixes on ENOENT handling,
batch isolation and startup snapshots.

## 4. Lifecycle

### 4.1 Inputs

Every instance watches, cluster-wide:

| Object | Used for |
|---|---|
| `Service` | selection (2.5), VIP (`status.loadBalancer.ingress[].ip`), ports, eTP |
| `EndpointSlice` (`discovery.k8s.io/v1`) | backends: `conditions.ready` (nil counts as ready), not terminating, `nodeName` = this node, port resolved by port name and protocol |
| `Node` | `node_ips` |
| `ServiceL2Status` (`metallb.io/v1beta1`), label `metallb.io/node=<NODE_NAME>` | whether this node announces the service's VIP |

`NODE_NAME` is mandatory for the L4 mode (the chart already injects it). Without
it the mode refuses to start rather than program every node.

### 4.2 Reconciliation

Level-triggered. Every informer event only marks the state dirty. A single sync
loop recomputes the desired state from the informer caches, coalescing bursts
(250 ms), and applies it as one transaction (3.3) when it changed. A failed pass
is retried after 5 s; a periodic resync (1 min) re-applies the state even
without events, so a table deleted or altered by hand comes back.

The first sync waits for every informer to be synced. Until then the table left
by the previous instance stays in place and keeps forwarding.

### 4.3 Conntrack purge

A conntrack entry outlives the rule that created it. The purge follows
kube-proxy. After every successful sync that withdrew something, and once after
the first sync, the mode deletes the conntrack entries that were translated by
this node (reply source differs from the original destination), towards a VIP
the mode knows (previous or current state), and:

- **TCP**: whose frontend is gone **on this node** — service removed or no
  longer managed, port removed, or this node no longer the announcer (MetalLB
  moved the VIP). A TCP backend withdrawn from a frontend that remains keeps its
  established connections until they end on their own, or until its pod goes;
  new connections no longer reach it.
- **UDP** (and any other protocol): whose backend is no longer programmed nor
  draining — gone from the EndpointSlices or not ready — or whose frontend is
  gone. Without the purge an active UDP flow would keep being sent to a backend
  that left, forever.

Why TCP is left alone: kube-proxy only purges UDP on endpoint removal, and the
lab showed the cost of doing otherwise. A backend taken out of a Service while
a request was in flight lost its flow at the purge, and the client, idle while
waiting for the answer, hung until its own timeout: the backend's reply matched
no entry any more, and no RST reached the client. Left alone, the request
completes.

A local UDP endpoint that is terminating is *draining*: it gets no new flow, but
its live ones are kept until it leaves the slices. An endpoint that is merely
not ready is not: its probe says it cannot serve.

Untranslated flows towards a VIP (a pod on a non-announcer node passing through)
are never touched, nor is anything the VM mode tracks. The purge runs after the
commit, so no new flow can be created towards a backend that was just purged.

### 4.4 Restart and upgrade of the DaemonSet

- Stopping an instance leaves the table in the kernel. A DaemonSet rolling
  update therefore does not interrupt traffic: the old rules keep forwarding until
  the new instance's first sync replaces them atomically. Changes that happen
  during the gap are applied with that delay, as with kube-proxy.
- The mode is behind `--enable-l4-loadbalancer` (chart:
  `l4LoadBalancer.enabled`), off by default. Disabling it deletes the table at
  startup, which is the rollback path for the whole mode.
- An instance with the mode disabled must not delete the table of another
  instance on the same node that runs it, as when the L4 mode is tried as a
  second release next to the platform's cozy-proxy: the table would only come
  back with the owner's next forced resync, up to a minute later, with neither
  guard nor translation for the VIPs in between. That instance runs with
  `--remove-l4-table-when-disabled=false` (chart:
  `l4LoadBalancer.removeTableWhenDisabled`) and leaves the table untouched, as
  an instance with the VM mode off leaves `cozy_proxy`.
- Nothing on the L4 side stops the process: the VM mode runs in the same
  manager. Without `NODE_NAME`, or while the MetalLB CRD is missing, the mode
  logs and stays idle.

### 4.5 Announcer changes

When MetalLB moves the VIP (node drain, backend moved), the new announcer
programs the DNAT on its next sync after its `ServiceL2Status` appears, and the
old one withdraws and purges. Connections in flight are lost, as with any L2
failover; new connections succeed once both the gratuitous ARP and the sync have
happened.

## 5. Source address, and what it means for security

| Client | Source seen by the backend | Cilium identity at the backend |
|---|---|---|
| Internet | its real IP | `world` |
| VM with a public IP (cozy-proxy VM mode) | the VM's public IP | `world` |
| pod, or node process, on any node | `100.64.0.x` of the announcer | `world` |

Consequences:

- **Reachability**: a pod of any tenant can reach any L4 service by its public
  IP, as from the Internet. That is the goal. ClusterIP traffic is unchanged and
  stays isolated.
- **CIDR allowlists now apply to in-cluster clients.** A tenant policy such as
  `ingressDeny fromCIDRSet 0.0.0.0/0 except <office>` is evaluated against
  `world` sources. With the VM mode today, an in-cluster client is seen as its
  node IP (`remote-node`), which such a rule does not match — it is bypassable.
  With the L4 mode the source is `world`, so the deny applies.
- **In-cluster clients are indistinguishable from one another.** Every pod and
  node process reaching a VIP through a given announcer shares its `100.64.0.x`
  address. An allowlist can admit "the cluster" (the join subnet) or not; it
  cannot admit one tenant's pods and not another's. Tenants that need that
  distinction must use ClusterIP and network policies, or mTLS.
- **ingress-nginx `whitelist-source-range`, Postgres `pg_hba`** and similar
  application-level allowlists see the same addresses as the network policies.
- **A tenant cannot switch its own LB to the L4 mode.** The kubevirt CCM
  copies every annotation of the tenant Service onto the infra Service, so a
  tenant controls `service.cilium.io/type` there — but not the labels: the CCM
  sets only its own (`cluster.x-k8s.io/tenant-service-*`, `cluster-name`) and the
  platform's `infraLabels`. cozy-proxy requires the
  `networking.cozystack.io/lb-proxy` label (2.5), so the annotation alone never
  makes it program anything. At worst a tenant copying `service.cilium.io/type:
  ClusterIP` makes its own LB dark (Cilium lets go, nobody takes over); an
  admission guard on CCM Services (7.1), where the platform runs one, refuses
  such a Service in the first place.
- **What the tenant still controls on an L4 CCM Service**: the ports (the CCM
  copies them) and `externalTrafficPolicy`. A tenant Service in eTP `Cluster`
  that the platform labelled anyway would be refused by cozy-proxy and stay
  dark, which is why the label and the annotation must be set per Service, for
  eTP `Local` only (7).

## 6. `externalTrafficPolicy`

| eTP | Behavior |
|---|---|
| `Local` | Phase 1. DNAT to local ready backends on the announcer; Internet and VM sources preserved. |
| `Cluster` | Not programmed (VIP guarded, traffic dropped) until a later phase. Supporting it requires DNAT to backends on other nodes. Their replies would leave through their own node's gateway and miss the announcer's conntrack, so **every** source would have to be masqueraded, losing the client IP — which is precisely what eTP `Cluster` means, but it changes what tenants see today. |

In production today, all Postgres and Ingress services and most CCM services use
`Local`. MariaDB (`Cluster` by default in the operator) and a minority of tenant
Kubernetes services (the CCM copies the tenant's policy) use `Cluster`.

## 7. Opting services in, per type

All of this is on the Cozystack side; cozy-proxy only reacts to the label and
the annotation. Each change sits behind one platform switch so that it can be
enabled per environment.

| Type | Where | Change |
|---|---|---|
| Postgres | `packages/apps/postgres/templates/external-svc.yaml` | add the label and the annotation; eTP is already `Local` |
| MariaDB | `packages/apps/mariadb/templates/mariadb.yaml` (`spec.service` / `spec.primaryService`) | add the label and the annotation through the operator's service template, and set `externalTrafficPolicy: Local` (operator default is `Cluster`) |
| Tenant Kubernetes (CCM) | CCM patch, next to the existing ones in `packages/apps/kubernetes/images/kubevirt-cloud-provider/patches`, switched on from `packages/apps/kubernetes/templates/cloud-config.yaml` | The CCM itself sets the label and `service.cilium.io/type: ClusterIP`, overriding any value copied from the tenant, and only when the tenant Service is eTP `Local`. `infraLabels` alone is not enough: it labels every Service of the cluster, eTP `Cluster` ones included, and the annotation would still have to come from the tenant. The CCM only sets labels and annotations at creation, so existing infra Services need a one-shot patch. See 7.1 for the Kyverno guard. |
| Ingress | `packages/extra/ingress/templates/nginx-ingress.yaml` | `controller.service.labels` / `annotations`; eTP is already `Local`. The host ingress (`tenant-root`) with PROXY protocol and ouroboros is last, see Open questions. |
| cozy-proxy | `packages/system/cozy-proxy` | bump the vendored chart, enable the mode, extend RBAC (EndpointSlices, Nodes, ServiceL2Status) |

### 7.1 Coexistence with an admission guard on CCM Services

Because the CCM copies every annotation of the tenant Service onto the infra
Service, a platform may run an admission guard against it. The one considered
here is a Kyverno `ClusterPolicy`: on CREATE and UPDATE, it refuses any Service
carrying `cluster.x-k8s.io/tenant-service-name` that has `spec.externalIPs` or
one of a list of MetalLB, external-dns and Cilium annotations,
`service.cilium.io/type` included, so that a tenant cannot drive them through
the CCM's copy. Such a guard, written that way, refuses an L4 CCM Service at
creation, and refuses the one-shot migration patch, which turns a compliant
Service into a violating one.

It does not refuse the UPDATEs that follow. Kyverno admits any UPDATE of an
object that already violates the rule (`validate.allowExistingViolations`,
`true` by default; verified on the lab with 1.18.2): the CCM's own port updates
pass, but so does an UPDATE that adds another refused key. On the lab, an L4
CCM Service, violating through its `service.cilium.io/type`, accepted
`service.cilium.io/node` on UPDATE, and another CCM Service already carried a
copied `metallb.io/loadBalancerIPs`. The narrowed rule below closes that hole for
L4 Services: with the label and `ClusterIP`, they are compliant, so every later
UPDATE is validated in full.

The two are reconciled by narrowing that one key rather than dropping it:

1. `service.cilium.io/type` leaves the guard's generic deny list, and gets a
   rule of its own: it is allowed only with the value `ClusterIP` **and** on a
   Service that also carries `networking.cozystack.io/lb-proxy: cozy-proxy`.
   Every other `service.cilium.io/*` key stays refused.
2. The label is set by the platform only (the CCM patch or the migration
   patch); the CCM copies no tenant label, so a tenant cannot satisfy the
   exception by itself.
3. The annotation is set by the CCM patch, overriding the tenant's value, rather
   than copied from the tenant. A tenant copying `ClusterIP` onto a Service the
   platform did not label is still refused.

A sketch of the dedicated rule (to be validated against the Kyverno version in
use, 1.18.2 when written):

```yaml
- name: cilium-type-only-for-l4
  match:
    any:
      - resources:
          kinds: ["Service"]
          operations: ["CREATE", "UPDATE"]
          selector:
            matchExpressions:
              - {key: cluster.x-k8s.io/tenant-service-name, operator: Exists}
  preconditions:
    all:
      - key: "{{ request.object.metadata.annotations.\"service.cilium.io/type\" || '' }}"
        operator: NotEquals
        value: ""
  validate:
    message: >-
      service.cilium.io/type is only allowed as ClusterIP on a LoadBalancer the
      platform handed to cozy-proxy (label networking.cozystack.io/lb-proxy).
    deny:
      conditions:
        any:
          - key: "{{ request.object.metadata.annotations.\"service.cilium.io/type\" }}"
            operator: NotEquals
            value: ClusterIP
          - key: "{{ request.object.metadata.labels.\"networking.cozystack.io/lb-proxy\" || '' }}"
            operator: NotEquals
            value: cozy-proxy
```

Order of the rollout: the narrowed policy goes in before the first CCM Service
is migrated, otherwise the migration patch is refused once the policy is
enforced, and reported as a violation while it is in `Audit`.

## 8. Migration and rollback, per service

Forward, for one service:

1. Add the label. Nothing happens: cozy-proxy ignores a labelled service without
   the annotation.
2. Add the annotation. Cilium withdraws the VIP and cozy-proxy programs it on its
   next sync (sub-second). Connections established through Cilium are not
   carried over and may be reset.

Rollback, for one service: **remove the annotation**. Cilium takes the VIP back
and cozy-proxy stops programming it at the same time (it requires both), then
purges its conntrack entries. Removing the label afterwards is cosmetic.

Removing only the label, on the other hand, leaves the VIP dark (Cilium still
ignores it): the runbook must always remove the annotation.

Whole mode: remove every annotation, then disable the mode (which deletes the
table).

For a CCM Service, the label and the annotation are both put on the infra
Service by the platform (7, 7.1), never through the tenant Service; the rollback
removes the annotation there, and the CCM patch must not put it back on its next
update.

## 9. Rollout plan

Each step runs for at least a week before the next, with the rollback above
rehearsed on the lab first.

0. **Lab**: a dedicated test service and a cozy-proxy instance with the mode
   enabled only on the lab. Matrix: Internet, pod on the announcer, pod
   elsewhere, VM client, multiple backends, backend deletion (purge), announcer
   failover, DaemonSet restart, ping and undeclared ports (no loop), CIDR deny
   policy.
1. **Postgres and MariaDB** (3 services in production): single port, TCP,
   single backend, low connection churn, clients mostly known. MariaDB first
   needs eTP `Local`.
2. **Tenant Kubernetes, CCM services with eTP `Local`**: port translation and
   several backends (worker VMs). Requires the CCM patch.
3. **Ingress**, tenant ingresses first, the host ingress last. This is where the
   risk is: 20 Ingress services carry most of the Internet-facing traffic.

At each step, compare before and after: reachability from the Internet and from
another tenant, the source IP logged by the backend, MetalLB announcer, and the
`cozy_proxy_l4` table on the announcer.

## 10. Open questions

1. **Announcer source.** Phase 1 reads MetalLB's `ServiceL2Status`. Upstream may
   prefer an abstraction (an interface with a MetalLB L2 implementation), and
   MetalLB BGP mode, where every node advertises, would need a different model.
2. **Pre-programming every node that has a local backend** would make failover
   hitless and remove the MetalLB dependency. It differs from the rejected E2
   (it does not masquerade the pod interface), but VM clients on a node holding
   a local backend would then be translated on their own node. That path has not
   been validated on the lab.
3. **Stale ARP after a failover**: a packet for a declared port reaching a node
   that no longer announces the VIP is routed back to the gateway until the
   caches expire (bounded by the TTL and MetalLB's gratuitous ARP). Should
   non-announcers drop VIP traffic that does not come from a local pod
   interface? That needs an interface name (`ovn0`), which is CNI specific.
4. **Host-network clients on the announcer** are not translated (no `output`
   hook). They reach the VIP only if the gateway hairpins the packet back. Add a
   `nat output` rule?
5. **eTP `Cluster`**: support it with full masquerade, keep refusing it, or have
   the charts force `Local`?
6. **Terminating endpoints**: fall back to serving-and-terminating backends when
   no ready one is left, as kube-proxy does for eTP `Local`?
7. **Node addresses**: only `InternalIP` today. Are there nodes whose pod egress
   is masqueraded to another address (multiple uplinks, `ExternalIP`)?
8. **Host ingress with PROXY protocol and ouroboros**: ouroboros handles hairpin
   traffic for the PROXY-protocol host ingress. Its interaction with a VIP that
   Cilium no longer owns has to be checked before step 3.
9. **Observability**: metrics (sync duration and errors, programmed services,
   purged flows) and Events on the Service when it is refused. Phase 1 only
   logs, once per change.
10. **Admission guard on CCM Services (7.1)**: the narrowed rule was tested on
    the lab on 2026-10-02 (Kyverno 1.18.2): a real CCM CREATE and port UPDATE,
    the migration patch, a tenant copy without the label, another
    `service.cilium.io/*` key, and the rollback in both orders. Cozystack does
    not ship such a guard today: should it, and in which package?
11. **Where the label lives**: `networking.cozystack.io/lb-proxy: cozy-proxy` is a
    proposal; the maintainers may prefer another key.
12. **Purging the TCP flows of a backend that is still alive — decided.** Aligned
    on kube-proxy (4.3): on endpoint removal only UDP flows are purged; TCP flows
    go with their frontend (service, port, announcement, including a MetalLB
    failover). Reason: kube-proxy behaves so, and on the lab an idle client of a
    withdrawn but live backend hung without a RST until its own timeout.
13. **Source-port reuse after masquerading node sources (fully-random).**
    Measured on the lab: 300 connections per second without keep-alive, for
    two minutes, from a pod to a CCM ingress in L4 mode. No error, but 0.06 to
    0.1 % of the connections took over a second, none under Cilium. On the
    announcer, the backend VM's SYN-ACK left its veth and never reached `ovn0`:
    it was dropped in OVS/OVN, and the client retransmitted. The tuples hit were
    `100.64.0.x:<port>`, reused 29 to 50 s after a previous connection on the
    same port.
    Cause, as far as the code goes: without a flag, the kernel's masquerade
    keeps the client's source port whenever *its own* conntrack has the tuple
    free (`nf_nat_l4proto_unique_tuple`), and it cannot see OVS's conntrack,
    which may still hold the previous connection. Every client of a node
    collapses onto one masqueraded address, so the source node's port choices
    turn into tuple reuse on the announcer. The suspected drop is the
    `ct.inv` match of the kube-ovn ACLs; that part is not confirmed.
    Fix in the prototype: `masquerade fully-random`
    (`NF_NAT_RANGE_PROTO_RANDOM_FULLY`, a fresh random port per flow;
    `random` alone only offsets from a hash). This breaks the correlation with
    the source node's choices, but a random port can still land on a tuple OVS
    tracks: the residual rate grows with the connection rate and with how long
    OVS keeps closed entries. To be measured again under the same load; if it
    persists, the next levers are on the OVN side (its conntrack timeouts or
    ACLs) or more masquerade addresses per announcer.
14. **`google/nftables` limits**: no `typeof` on sets, and no direction on the
    typed conntrack keys (3.1). Both are cosmetic for `nft list` today; fixing
    them upstream would let the masquerade match the original destination.

## 11. Prototype status

Branch `feat/l4-loadbalancer`, phase 1 only:

| Area | Where | Tests |
|---|---|---|
| Selection (2.5) | `pkg/l4/select.go` | unit |
| Desired state per node (4.1) | `pkg/l4/state.go` | unit |
| Purge decision (4.3) | `pkg/l4/conntrack.go` | unit |
| nftables table (3) | `pkg/proxy/l4_nft.go` | kernel, in a network namespace: `nft list` against golden files, and real TCP traffic through three namespaces (translation, round-robin, source kept or masqueraded, guard, port without backend, purge, rebuild with an open connection) |
| Conntrack purge | `pkg/proxy/conntrack.go` | kernel, in a network namespace |
| Controller (4.2) | `pkg/controllers/l4_controller.go` | unit, and fake API clients |
| Switch and RBAC | `main.go`, chart `l4LoadBalancer.enabled` | `helm template` |

The kernel tests need root and skip otherwise; `nft list` comparisons also need
the `nft` binary. They run in a privileged Linux container, for instance:

```
docker run --rm --privileged -v "$PWD":/src -w /src golang:1.26 sh -c \
  'apt-get update -qq && apt-get install -y -qq nftables && go test ./...'
```

Not in phase 1: UDP, eTP `Cluster`, IPv6, terminating endpoints, metrics and
Events.

Lab run on 2026-10-02 (image built from `181b41c`, as a second release with the
VM mode off, next to the platform's cozy-proxy):

| Case | Result | Source seen by the backend |
|---|---|---|
| Internet, both ports (port translation 80 -> 8080, 81 -> 9090) | OK | the client's public IP |
| pods on the 3 nodes, another tenant | OK | `100.64.0.x` of the announcer |
| VM-mode client on another node, and on the announcer | OK | the VM's public IP |
| round-robin between the announcer's two local backends | OK | |
| undeclared port, ping (tcpdump on the announcer and on another node) | dropped, no packet sent back out | |
| CIDR deny `0.0.0.0/0 except <client>` on the backend | pods and VM refused, the allowed client passes | |
| backend withdrawn | its flows purged, new connections go to the others (built from `181b41c`; since then TCP flows of a withdrawn backend are kept, see 4.3) | |
| announcer moved by MetalLB | one failed probe out of ~110 (0.5 s interval) | |
| rollout restart of the DaemonSet | open connection kept, 0 failed probes out of 113 | |
| Postgres app, psql from pods, VM and VPN; `pg_stat_activity` | OK | `100.64.0.x`, VM IP, VPN address |
| CNPG switchover | ~7 s unavailable, mostly the server shutting down | |
| rollback (annotation removed) | Cilium serves the VIP again, other tenants refused again | |

Two bugs were found and fixed: a chain named after an nft keyword (`dnat`),
which nft could not name on the command line, and a misleading logger name.

