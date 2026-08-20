# Higress gateway

Higress chart `2.2.4` is installed from the official `higress.io` repository.
The values use one low-resource gateway/controller/pilot replica and NodePorts
`30080`/`30443` because the IDC cluster has no cloud LoadBalancer. The demo
Ingress is intentionally kept in the demo namespace so its Service and TLS
Secret are same-namespace resources. The console and plugin server stay at
zero replicas in this infrastructure-only PoC.

The install script generates a self-signed certificate locally and creates it
in the cluster; no certificate or key is committed to Git.
