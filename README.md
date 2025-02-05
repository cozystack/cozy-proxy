# cozy-proxy

A simple kube-proxy addon for 1:1 NAT services in Kubernetes using an NFT backend.

This project ensures a one-to-one mapping between a service and a pod in Kubernetes.

## Why

At [Cozystack](https://cozystack.io), we strive to follow the standard Kubernetes network architecture by separating the pod network, service networks, and external load balancers. However, our platform also runs virtual machines that sometimes require an external IP address.

There are several ways to achieve this:
- Using a separate Kube-OVN subnet and exposing it via BGP with kube-ovn-speaker.
- Adding a secondary interface with Multus.
- Using native Kubernetes services with externalIPs and exposing them via MetalLB.

The last option is the simplest and most flexible, but it has a limitation: Kubernetes services do not forward all traffic—only traffic on specific ports (see: [Kubernetes Issue #23864](https://github.com/kubernetes/kubernetes/issues/23864)). Additionally, kube-proxy does not perform SNAT, which causes outgoing traffic from the pod to use the node’s default IP.

To address these issues, we have added an additional controller that performs 1:1 NAT for services annotated with `networking.cozystack.io/wholeIP=true`.

## How It Works

cozy-proxy is a simple Kubernetes controller that watches for services with the `networking.cozystack.io/wholeIP=true` annotation. When it finds such a service, it creates an NFT rule that forwards all traffic from the service's external IP to the pod's IP and vice versa. It also disables connection tracking (conntrack) for traffic between the service and the pod, offloading that work to NFTables.

This controller can be used together with kube-proxy and Cilium in kube-proxy replacement mode.

## Environment

This controller was developed primarily for the Cozystack platform and has been tested in the following environment:
- **OS**: Talos Linux
- **CNI**: Kube-OVN with Cilium in chaining mode.
- **Kube-proxy**: Cilium in kube-proxy replacement mode.
- **LoadBalancer**: MetalLB in L2 mode with `externalTrafficPolicy: Local`.

*If you have tested it in other environments, please let us know.*

## Credits
- [@kvaps](https://github.com/kvaps) – for the implementation.
- [@hexchain](https://github.com/hexchain) – for the [Stateless NAT with NFTables](https://wiki.hexchain.org/linux/networking/nft-stateless-nat/) snippet.
- [@danwinship](https://github.com/danwinship) – for the [idea regarding the annotation](https://github.com/kubernetes/kubernetes/issues/23864#issuecomment-2607297206).
