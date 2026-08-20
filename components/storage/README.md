# Open-Local storage

This PoC uses Open-Local `v0.7.1` with the LVM backend. Each node must expose an
unused block device at `/dev/vdb`; Open-Local creates/manages the per-node
volume group `open-local-pool-0` and the `open-local-lvm` StorageClass.

The upstream chart is fetched at install time from the pinned Git tag. Set
`OPEN_LOCAL_CHART` to a local chart directory for an offline install. The chart
uses `extender.init_job=false` because the upstream init job edits kubeadm
static scheduler manifests and is not safe on k3s. The CSI/kubelet directory
defaults to `/var/lib/kubelet`; set `OPEN_LOCAL_KUBELET_DIR` when the k3s node
was installed with a custom `--root-dir`.

Open-Local v0.7.1 predates Kubernetes 1.34 in its compatibility matrix. This
repository keeps the requested version for the PoC and records the actual
cluster result in `components/storage/artifacts/` during verification.
