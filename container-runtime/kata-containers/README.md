# kata-containers extension

## Installation

See [Installing Extensions](https://github.com/siderolabs/extensions#installing-extensions).

## Usage

This fork exposes the Codewire runtime handler names used by the dev runtime
profiles:

- `kata-clh` uses the Cloud Hypervisor configuration for commodity workloads.
- `kata-qemu-snp` uses the QEMU-SNP configuration, the SNP experimental QEMU
  binary, AMD SEV firmware, and the confidential guest image.

## Testing

Apply the following manifest to run nginx pod using Kata Containers:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata
handler: kata
overhead:
    podFixed:
        memory: "130Mi"
        cpu: "250m"
---
apiVersion: v1
kind: Pod
metadata:
  name: nginx-kata
spec:
  runtimeClassName: kata
  containers:
  - name: nginx
    image: nginx
```

The pod should be up and running:

```bash
$ kubectl get pods
NAME           READY   STATUS    RESTARTS   AGE
nginx-kata     1/1     Running   0          40s
```
