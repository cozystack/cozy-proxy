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

To address these issues, we have added an additional controller that performs 1:1 NAT for services annotated with `networking.cozystack.io/wholeIP=true`.

## How It Works

cozy-proxy is a simple Kubernetes controller that watches for services with the `networking.cozystack.io/wholeIP=true` annotation. When it finds such a service, it creates an NFT rule that forwards all traffic from the service's external IP to the pod's IP and vice versa. It also disables connection tracking (conntrack) for traffic between the service and the pod, offloading that work to NFTables.

This controller can be used together with kube-proxy and Cilium in kube-proxy replacement mode.

## Installation

Install controller using Helm-chart:

```bash
helm install cozy-proxy charts/cozy-proxy -n kube-system
```

## Usage

Create a LoadBalancer service with `networking.cozystack.io/wholeIP=true` annotation:

```yaml
apiVersion: v1
kind: Service
metadata:
  annotations:
    networking.cozystack.io/wholeIP: "true"
  name: example-service
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
