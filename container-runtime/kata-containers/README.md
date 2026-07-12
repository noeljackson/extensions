# kata-containers extension

## Installation

See [Installing Extensions](https://github.com/siderolabs/extensions#installing-extensions).

## Usage

This fork exposes the Codewire runtime handler names used by the dev runtime
profiles:

- `kata-clh` uses the Cloud Hypervisor configuration for commodity workloads.
- `kata-qemu-snp` uses the QEMU-SNP configuration, the SNP experimental QEMU
  binary, AMD SEV firmware, and the confidential guest image.

Both configurations allow only the `cc_init_data` hypervisor annotation in
addition to their upstream defaults. Codewire uses that standard Kata transport
for guest Agent Policy; it does not enable a wildcard annotation surface.

The confidential handler also installs `nydus-for-kata-tee` and configures only
`kata-qemu-snp` to use that snapshotter. Do not make nydus the global
containerd snapshotter. `runc` stays on the Talos default snapshotter, and
`kata-clh` is intended to move to devmapper/dm-thin once the host thin-pool is
provisioned before containerd starts.

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
