# OpenKruise

The pinned OpenKruise chart is `1.9.1`. The values keep one controller replica
for the 4C/4Gi PoC and point `kruise-daemon` at k3s' runtime socket directory
(`/run/k3s`). With an empty `daemon.socketFile`, the chart's runtime detector
uses k3s' `containerd/containerd.sock` below that directory. Override the
values file when the node uses a different k3s runtime path.

`cloneset-smoke.yaml` is a one-pod CloneSet used by the verification script to
prove an in-place image update without changing the Pod name.
