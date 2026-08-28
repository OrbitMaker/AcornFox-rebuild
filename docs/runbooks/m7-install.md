# M7 RC 安装 runbook

状态：`RUNBOOK_CONTRACT_ONLY`，当前执行状态：`NOT_RUN`。本文描述 `INSTALL-001`（在线明确网络）、
`INSTALL-002`（离线 bundle）和 `INSTALL-003`（默认保留数据卸载）的真实验收
顺序；在干净 Ubuntu 24.04 amd64 主机完成并留存独立 evidence 前，不得写
`PASS`。

## 0. 边界与前置

RC 验收主机为 Ubuntu 24.04 LTS amd64；bundle 另提供已校验的 Linux arm64
交叉构建清单。`install-host.sh` 可在线安装或从 checksum-covered deb 目录离线
安装 Docker/PostgreSQL/AppArmor 前置，四个
unit 必须是 `open-card-server.service`、`open-card-agent.service`、
`open-card-buildkit.service` 和 `open-card-caddy.service`。安装根目录契约为：

- `/opt/open-card`：不可变 release 目录及 `current`/`previous` 指针；
- `/etc/open-card`：配置；
- `/var/lib/open-card`：控制面数据、backups、evidence 和应用事实。

只在明确的干净验收主机执行。共享开发机只允许执行带
`--test-safe-prefix` 的 user-space dry-run，不可激活宿主 systemd。

## 1. 安装前检查

```bash
set -euo pipefail
ROOT=/tmp/open-card-g7-install
SAFE_PREFIX=/tmp/open-card-g7-fixture
BUNDLE=/tmp/open-card-g7-fixture/bundle
bash scripts/mvp/install.sh --root "$ROOT" --bundle "$BUNDLE" \
  --test-safe-prefix "$SAFE_PREFIX" --dry-run
```

dry-run 必须验证 root 是绝对路径、bundle manifest 的完整文件集合、SHA-256、
文件 mode、无 symlink/路径穿越，并且不创建 unit、账号、目录或服务进程。
bundle manifest 的 `product`、版本、data compatibility 和 Agent protocol
窗口必须与当前数据/Agent 事实兼容。

## 2. 在线/离线安装

`INSTALL-001` 只在验收环境已显式允许网络时使用 `--url`；不得把环境代理、
公网 DNS 或未固定下载当作 supply chain 证据。`INSTALL-002` 必须断开外部
网络，仅提供 checksum 已验证的本地 bundle：

```bash
# online-explicit（仅干净验收主机；digest 来自独立发布通道）
OPEN_CARD_INSTALL_CONFIRMATION=OPEN-CARD-INSTALL \
bash scripts/mvp/install-host.sh --url "$PINNED_BUNDLE_URL" \
  --expected-manifest-sha256 "$PUBLISHED_MANIFEST_SHA256" \
  --migration-command /opt/open-card-installer/control-plane-migrate.sh \
  --migration-dir /opt/open-card-installer/migrations/current

# offline-bundle（网络策略已拒绝外连）
OPEN_CARD_INSTALL_CONFIRMATION=OPEN-CARD-INSTALL \
bash scripts/mvp/install-host.sh --bundle "$BUNDLE" --offline \
  --expected-manifest-sha256 "$PUBLISHED_MANIFEST_SHA256" \
  --debs-dir "$OFFLINE_DEBS_ROOT" --debs-sha256 "$OFFLINE_DEBS_ROOT/debs.sha256" \
  --migration-command "$MIGRATE_COMMAND" --migration-dir "$MIGRATIONS_CURRENT"
```

安装先 stage release，再原子切换 `current`；只有 `--activate` 且 root 是
通过精确 `OPEN-CARD-INSTALL` 确认且提供外部 manifest SHA 时，才创建账号、
写 systemd unit、daemon-reload、enable/restart 四个服务。clean-worker marker
仅是验收兼容路径，不是生产安装前置。记录 manifest、每个文件 checksum/mode、版本、迁移
版本、`systemctl is-enabled/is-active` 和健康检查输出。

## 3. 安装后检查与失败处理

必须独立确认：四个 unit active/enabled、Caddy 仅 loopback、Agent 仅受控
Docker 权限、BuildKit rootless/no-network 边界、控制面健康、当前 release
身份和数据库迁移版本一致。任一 checksum、权限、兼容性、迁移或健康检查失败
都必须保留旧指针/未激活状态，结果标为失败；不得用 HTTP 200 或“进程存在”
替代文件、systemd、数据库和审计证据。

## 4. `INSTALL-003` 卸载

默认卸载只移除 binaries/config/unit，保留 `/var/lib/open-card`、backups、
evidence 和应用数据事实：

```bash
bash scripts/mvp/uninstall.sh --root "$ROOT" \
  --test-safe-prefix "$SAFE_PREFIX" --dry-run
```

真实执行前先导出目录快照和 checksum。危险清理不是默认路径，只有明确的
`--purge --confirm OPEN-CARD-PURGE` 才允许删除数据；未提供精确确认必须
fail-closed。卸载后的证据应证明 unit 已移除、daemon-reload 已执行、数据仍
可被同版本重新安装发现。
