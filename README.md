# cozy-proxy

A simple kube-proxy addon for 1:1 NAT services in Kubernetes using an NFT backend.

This project ensures a one-to-one mapping between a service and a pod in Kubernetes.

## Why

At [Cozystack](https://cozystack.io), we strive to follow the standard Kubernetes network architecture by separating the pod network, service networks, and external load balancers. However, our platform also runs virtual machines that sometimes require an external IP address.

There are several ways to achieve this:
- Using a separate Kube-OVN subnet and exposing it via BGP with kube-ovn-speaker.
- Adding a secondary interface with Multus.
- Using native Kubernetes services with externalIPs and exposing them via MetalLB.

The last option is the simplest and most flexible, but it has a limitation: Kubernetes services do not forward all traffic,
but only traffic on specific ports (see: [Kubernetes Issue #23864](https://github.com/kubernetes/kubernetes/issues/23864)).
Additionally, kube-proxy does not perform SNAT, which causes outgoing traffic from the pod to use the default gateway of the host where it is running.

To address these issues, we have added an additional controller that performs 1:1 NAT for services selected by either the `service.kubernetes.io/service-proxy-name: cozy-proxy` label or the `networking.cozystack.io/wholeIP` annotation.

## How It Works

cozy-proxy is a simple Kubernetes controller that watches for services selected by either of the following:

- **`service.kubernetes.io/service-proxy-name: cozy-proxy`** label (recommended) — the standard Kubernetes mechanism for delegating a service to a non-default proxy. kube-proxy skips services carrying this label, so cozy-proxy becomes the sole handler and no rules collide.
- **`networking.cozystack.io/wholeIP`** annotation — also selects the service for management. The annotation value additionally drives the ingress mode (see below).

When it finds such a service, it creates NFT rules that forward traffic from the service's external IP to the pod's IP and vice versa, performing source-IP preservation for egress traffic.

This controller can be used together with kube-proxy and Cilium in kube-proxy replacement mode.

### Which selector should I use?

- If your cluster runs **plain kube-proxy** (iptables or IPVS mode) — for example, a default RKE2/kubeadm install with Calico or Flannel — use the `service.kubernetes.io/service-proxy-name: cozy-proxy` label. Without it, kube-proxy installs its own LoadBalancer rules that conflict with cozy-proxy's NAT and break outbound SNAT.
- If your cluster runs **Cilium in kube-proxy replacement mode** (as in the reference Cozystack environment), either selector works.

You can safely set both on the same service.

## Ingress mode

The `networking.cozystack.io/wholeIP` annotation value selects the ingress mode:

| Value     | Behavior                                                                                                        |
|-----------|-----------------------------------------------------------------------------------------------------------------|
| `"true"`  | **Whole-IP passthrough.** All TCP/UDP traffic to the LoadBalancer IP is forwarded to the backend pod.           |
| `"false"` | **Per-port filtering.** Only TCP/UDP traffic to ports listed in `Service.spec.ports` is forwarded; rest dropped.|
| absent    | Defaults to **passthrough** (services selected by label only behave the same as `wholeIP: "true"`).             |

In both managed modes, egress traffic from the backend pod is SNATed to the
LoadBalancer IP for source-IP preservation.

The optional `networking.cozystack.io/allowICMP: "true"` annotation, only
meaningful in port-filter mode (`wholeIP: "false"`), accepts ICMP traffic
toward the backend pod IP that would otherwise be dropped by the per-port
filter. Without it, all ICMP to a port-filtered pod is dropped — which also
blocks `ping`, **PMTU discovery** (ICMP "fragmentation needed"), and ICMP
unreachable signalling. Recommended for any service where path-MTU mismatches
or observability matter.

## Datapath

The nftables ruleset placed in table `ip cozy_proxy` consists of:

- Chain `egress_snat` at priority `raw` (-300): rewrites packet source IP via
  the `pod_svc` map for outbound traffic from managed pods. Runs before
  conntrack so the recorded tuple has `saddr=LB_IP`.
- Chain `ingress_dnat` at priority `mangle` (-150): rewrites packet
  destination IP via the `svc_pod` map for inbound traffic to a LoadBalancer
  IP. Runs after conntrack so reply packets of egress flows are matched
  correctly.
- Chain `port_filter` at priority `filter` (0): for Services in port-filter
  mode (`wholeIP: "false"`), drops ingress packets whose
  `(daddr, l4proto, dport)` is not in `allowed_ports`. The chain accepts
  packets in conntrack states `established` or `related` first, so reply
  packets of egress flows bypass the filter even when their dport is the VM's
  ephemeral source port. ICMP is dropped by default; if the
  `allowICMP: "true"` annotation is set, the pod IP is added to
  `icmp_allowed_pods` and ICMP toward it is accepted before the drop rule.

## Installation

Install controller using Helm-chart:

```bash
helm install cozy-proxy charts/cozy-proxy -n kube-system
```

## Usage

Create a LoadBalancer service with the `service.kubernetes.io/service-proxy-name: cozy-proxy` label. This also tells kube-proxy to stay away from the service. The `networking.cozystack.io/wholeIP: "true"` annotation is shown for clarity but is optional when the label is present:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: example-service
  labels:
    service.kubernetes.io/service-proxy-name: cozy-proxy
  annotations:
    networking.cozystack.io/wholeIP: "true"
spec:
  allocateLoadBalancerNodePorts: false
  externalTrafficPolicy: Local
  ports:
  - port: 65535 # any
  selector:
    app: nginx
  type: LoadBalancer
---
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: docker.io/library/nginx:alpine
```

Check that the service has an external IP:

```bash
kubectl get svc
```

Example output:

```console
NAME              TYPE           CLUSTER-IP     EXTERNAL-IP     PORT(S)     AGE
example-service   LoadBalancer   10.96.195.46   1.2.3.4         65535/TCP   84s
```

Now try to access the service using `icmp` and `tcp`; both should work:

```bash
ping 1.2.3.4
curl 1.2.3.4
```

Check external IP from inside the pod:

```bash
kubectl exec -ti nginx -- curl icanhazip.com
```

Example output would be the same as the service external IP:
```console
1.2.3.4
```

## Environment

This controller was developed primarily for the [Cozystack](https://cozystack.io) platform and has been tested in the following environment:
- **OS**: Talos Linux
- **CNI**: Kube-OVN with Cilium in chaining mode.
- **Kube-proxy**: Cilium in kube-proxy replacement mode.
- **LoadBalancer**: MetalLB in L2 mode with `externalTrafficPolicy: Local`.

*If you have tested it in other environments, please let us know.*

## Credits
- [@kvaps](https://github.com/kvaps) – for the implementation.
- [@hexchain](https://github.com/hexchain) – for the [Stateless NAT with NFTables](https://wiki.hexchain.org/linux/networking/nft-stateless-nat/) snippet.
- [@danwinship](https://github.com/danwinship) – for the [idea regarding the annotation](https://github.com/kubernetes/kubernetes/issues/23864#issuecomment-2607297206).
