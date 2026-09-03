# kata-containers extension

This extension packages both the standard Cloud Hypervisor runtime and a
confidential QEMU SEV-SNP runtime from the Kata Containers release payload.

## Installation

See [Installing Extensions](https://github.com/siderolabs/extensions#installing-extensions).

## Usage

The extension exposes these explicit runtime handlers:

- `kata-clh` uses the Cloud Hypervisor configuration for commodity workloads.
- On x86_64, `kata-qemu-snp` uses the QEMU-SNP configuration, the SNP
  experimental QEMU binary, AMD SEV firmware, and the confidential guest image.

The SEV-SNP handler and its nydus snapshotter are omitted from ARM64 builds;
the standard Kata and `kata-clh` handlers remain available there.

Both configurations retain the `cc_init_data` and `kernel_params` hypervisor
annotations used for Agent Policy and confidential guest configuration. The
package test rejects wildcard annotation patterns.

The confidential handler also installs `nydus-for-kata-tee` and configures only
`kata-qemu-snp` to use that snapshotter. Do not make nydus the global
containerd snapshotter. `runc` and `kata-clh` stay on the Talos default
snapshotter.

Talos does not ship `/bin/sh`, so the `mount.fuse` helper is a static wrapper
that execs `nydus-overlayfs` directly instead of using libfuse's shell-based
helper.

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
