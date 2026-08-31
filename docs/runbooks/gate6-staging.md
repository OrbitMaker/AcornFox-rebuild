# Gate 6 staging evidence acceptance

Status: `RUNBOOK_CONTRACT_ONLY` / `NOT_RUN`.

This runbook defines the pre-DNS staging evidence sequence. It has not been
executed against any provider, a staging server, a firewall, public DNS, or a
browser. A command exit or a receipt file by itself is not acceptance; the
final validator must verify all five target receipts and three signed
outside-target observations.

## Release boundary

The existing `v0.8.0-rc.1` tag predates Gate 6 host admission and evidence
code. Do not deploy it while claiming this runbook was exercised. Build and
independently certify a future `v0.8.0-rc.N` candidate first, then freeze:

- annotated tag and dereferenced source commit;
- AMD64 release manifest and production archive;
- bundle-manifest SHA-256;
- clean source clone used by the target receipt builder.

The identity JSON contains those non-secret facts plus the selected target. The
legacy Tencent v1 target contains provider, product, instance ID and public
IPv4. The v2 target additionally binds `account_id`, `region` and RFC1918
`private_ipv4`; its normalized provider/product must be lowercase. It contains
absolute local paths used by the builder, so it remains root-only evidence input
and is never copied into a receipt.

## Target and firewall prerequisite

Before any resource query, select the exact provider, account, region, product,
instance, public IPv4 and (for v2) private IPv4. Keep the sequence
pre-DNS: the final manifest remains `production_accepted=false`, and this
runbook authorizes neither DNS nor installation.

### Tencent CVM or Lighthouse branch

Before any resource query, select the exact Tencent profile, account, region,
product (`cvm` or `lighthouse`) and instance. Read identity and inventory with
the official CLI. Capture the exact old firewall/security-group rule snapshot
and render a plan locally:

```bash
tools/evidence/g6_firewall_plan.py \
  --input /absolute/root-only/firewall-input.json \
  --output /absolute/new/firewall-plan.json
```

The output must remain `DRAFT_UNEXECUTABLE`. Re-read identity and old rules,
show the exact additions/removals and rollback snapshot, then obtain separate
user confirmation before any later provider-specific write. This runbook does
not authorize that write and never writes DNS.

`g6_firewall_plan.py` remains Tencent-only. Do not use it to model Alibaba
security-group changes.

### Alibaba ECS branch

Use an external, read-only security-group snapshot and independently preserve
the selected v2 target. No Alibaba CLI query or cloud write is run by these
evidence tools. The current positive local fixture is:

```json
{
  "provider": "aliyun",
  "product": "ecs",
  "account_id": "<account-id>",
  "region": "cn-shanghai",
  "instance_id": "i-REDACTED",
  "public_ipv4": "<server-ip>",
  "private_ipv4": "172.20.81.108"
}
```

Alibaba security-group mutation, DNS, and installation need separate explicit
authorization. If the target is reachable only inside its VPC, use a separately
authorized private jump SSH path; do not treat that path as public reachability
evidence.

## Target phase sequence

Run the collector from the future certified release. Production receipts are
fixed below `/var/lib/open-card/evidence/gate6/<run-id>`.

### 1. Read-only preinstall snapshot

```bash
scripts/mvp/g6-staging-evidence.sh \
  --phase snapshot-preinstall \
  --identity /absolute/root-only/identity-preinstall.json \
  --confirm G6-SNAPSHOT-READONLY
```

The collector runs the frozen host admission check and the builder proves the
annotated tag, release, archive, bundle and absence of a prior installation or
colocated workload.

### 2. Checksum-pinned install, then read-only verification

Run `install-host.sh` with the exact manifest SHA, dedicated-host confirmation,
root-only administrator password input, HTTPS origin, Edge domain and fixed
migration inputs. The installer persists the accepted post-prerequisite host
receipt at `/var/lib/open-card/evidence/host-preflight.json`.

```bash
scripts/mvp/g6-staging-evidence.sh \
  --phase install-verify \
  --identity /absolute/root-only/identity-installed.json \
  --app-host app.staging.example \
  --session-cookie-file /absolute/root-only/session.cookie \
  --confirm G6-INSTALL-VERIFY-READONLY
```

This phase requires the exact five service units and
`open-card-upgrade-safe.target` active and enabled, relative activation
pointers, no upgrade marker, healthy loopback API, authenticated SSE headers,
and a successful internal application route.

### 3. Service restart drill

The raw installation ID is read from the root-only installation file and is
used only in the one-time operator confirmation. It is never written to the
receipt.

```text
--confirm G6:restart-services:<exact-installation-id>
```

The collector restarts BuildKit, server, Agent and RouteProvider, then Edge
last, and captures the complete post-restart facts. Replaying a completed phase
does not restart services again. A durable one-use marker is written before the
first restart and removed only after the receipt commits. If a process or host
failure leaves that marker without a receipt, stop for recovery review instead
of repeating the restart blindly.

### 4. Reboot handoff and separate reboot

Create the durable handoff first using:

```text
--confirm G6:reboot:<exact-installation-id>
```

The collector deliberately does not reboot the host. After the handoff receipt
exists and the exact target has been reconfirmed, the separately authorized
operator action is:

```bash
sudo /usr/bin/systemctl reboot
```

After reconnecting, run `reboot-verify` with
`G6-REBOOT-VERIFY-READONLY`. The builder requires a different boot ID and the
same release, installation and activation identities.

## Signed outside-target observations

The target host cannot create evidence for its own public reachability. From a
separately identified observer, collect all three methods:

1. `curl_resolve`: HTTP/HTTPS and hosts-file/`curl --resolve` observations;
2. `external_tcp`: approved 80/443 reachable and forbidden ports closed;
3. `browser`: screenshot or trace plus machine-readable DOM assertions.

Each canonical statement is signed with an observer Ed25519 key using the
`open-card-g6` OpenSSH namespace. Import it with
`g6_import_external.py --allowed-signers ... --signature ...`. Private signing
keys stay on the outside observer and are never copied into target evidence.

Finally invoke `g6_validate.py finalize` with receipts in exact sequence 1–8
and the same trusted allowed-signers file. The resulting manifest remains
`production_accepted=false` with scope `staging_pre_dns_only`.

## Stop conditions

Stop without DNS or firewall mutation when any fact is missing, a unit is only
active or only enabled, a pointer is absolute, the upgrade marker exists, the
boot ID did not change, an external signature fails, a forbidden port is
reachable, or browser/API/SSE/application evidence is incomplete. Retain the
root-only evidence directory for diagnosis; do not rewrite a failed or partial
run into PASS.
