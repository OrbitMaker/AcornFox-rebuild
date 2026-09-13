# AcornFox 离线宿主发布制品与签名索引构建指南

本文档说明离线宿主发布工具 `cmd/acornfox-host-release` 的设计、规范、安全约束与操作流程。

本工具为发布操作员（release operator）专用离线工具，与运行时宿主状态机（`internal/desktopupdate`）分离。它严格复用已导出的校验接口 `desktopupdate.VerifyHostBundle` 与 `desktopupdate.VerifyAndSelectUpdate`，不修改运行时控制器状态或宿主槽位（HostSlots）。

---

## 1. 总体设计与职责边界

`acornfox-host-release` 提供三个内聚子命令：

1. **`build`**：从显式构建清单元数据（Spec）与载荷树（Payload Tree）构建确定性的 `gzip/tar` 宿主制品（`.tar.gz`），并通过内存中的临时密钥对与 `VerifyHostBundle` 执行本地自检，确保输出完全符合验证器规则。
2. **`sign-index`**：将规范 JSON `IndexPayload` 用操作员提供的离线 Ed25519 私钥签名，生成现有的 `IndexEnvelope`（schema 1），并在写入前使用 `VerifyAndSelectUpdate` 与操作员策略输入完成全量策略校验。
3. **`verify-bundle`**：使用签名信封与公钥，通过 `VerifyHostBundle` 离线校验已有制品文件的完整性与元数据。

### 当前支持的目标平台

- `darwin/arm64`（macOS Apple Silicon）
- `linux/amd64`（Linux x86_64）
- `linux/arm64`（Linux AArch64）

---

## 2. 载荷目录规范与安全约束

载荷目录（`--payload-dir`）包含要打包进入宿主制品的各组件文件。

### 目录与文件约束

- **文件类型**：必须全部为普通文件（regular file）。严禁符号链接（symlink）、硬链接（hard link）或特殊文件（device、FIFO、socket）。
- **权限规范**：
  - 可执行文件必须为 `0755`（`rwxr-xr-x`）。
  - 普通数据文件必须为 `0644`（`rw-r--r--`）。
  - 严禁 setuid、setgid 或 sticky 权限。
- **路径约束**：
  - 路径前缀仅允许 `launcher/`、`controller/` 或 `backend/candidate/`。
  - 严禁路径穿越（`..`）或绝对路径。
  - 路径中不得包含敏感保留标识（如 `userdata`、`secrets`、`ssh`、`vm`、`seed`、`rootfs`、`.key`、`.img`、`.iso` 等）。
  - 单个成员路径长度不超过 240 字符，每个路径分段不超过 100 字符。
- **数量与大小约束**：
  - 文件总数必须在 2 到 4096 之间。
  - 单个成员大小不超过 1GB。
  - 展开总大小不超过 4GB。
  - 清单元数据 `bundle.json` 大小不超过 2MB。

### 关键成员说明

1. **启动器（Launcher）**：
   - 路径必须以 `launcher/` 为前缀（例如 `launcher/AcornFox` 或 `launcher/acornfox`）。
   - 权限必须为 `0755`。
2. **控制器（Controller）**：
   - 路径必须严格为 `controller/acornfox-host-update`。
   - 权限必须为 `0755`。
3. **后端（Backend）**：
   - **`unchanged` 模式**：载荷树中**严禁包含**任何 `backend/` 前缀文件。此时 `from_binding == to_binding`，`helper_sha256` 为空。
   - **`candidate` 模式**：载荷树中必须且仅包含 `backend/candidate/` 下的 6 个扁平文件：
     1. `backend/candidate/candidate-binding.json`
     2. `backend/candidate/candidate-binding.sha256`（内容为 `<to_binding>\n`）
     3. `backend/candidate/release-manifest.json`（必须包含 `bin/acornfox-upgrade`，权限 `0755`，哈希与 `helper_sha256` 一致）
     4. `backend/candidate/bundle-manifest.sha256`
     5. `backend/candidate/build-record.json`
     6. `backend/candidate/acornfox-<Version>-production.tar.gz`

---

## 3. 确定性归档生成、固定根与无覆盖原子写入

### 确定性归档（Deterministic Archive）

为了确保相同源码与输入生成完全一致的字节（byte-for-byte identical）：
- **Tar 头格式**：首项固定为 `bundle.json`，后接按路径字典序严格升序排列的文件。
- **时间戳与属性消除**：所有 Tar Header 的 `ModTime` 统一固定为 Unix Epoch（`1970-01-01T00:00:00Z`），`Uid`/`Gid` 置 `0`，`Uname`/`Gname` 置空，消除 PAXRecords。
- **Gzip 头固定**：Gzip Header 的 `OS` 固定为 `255`（unknown），`ModTime` 固定为 Epoch，`Name`/`Comment` 置空，采用标准压缩级别。

### 固定源根防路径竞态（os.OpenRoot Pinning）

- 构建过程使用 Go 1.25 标准库 `os.OpenRoot` 固定载荷根目录，从 `Root.FS` 相对枚举并从 `Root` 打开相对成员。
- 打开后逐项核对打开文件与 Lstat 的 `os.SameFile`、inode、常规文件属性、模式、大小及 `Nlink == 1`（无硬链接），彻底杜绝祖先目录或文件替换导致的源根外泄漏。
- 构建时深度扫描成员内容，若发现任何包含私钥标记（如 `PRIVATE KEY` 或可解析的 PEM 块）的文件立即中断拒绝，私钥绝不允许进入载荷树或制品。

### 原子无覆盖写入（Atomic No-Clobber）与输出目录权限保护

- 输出父目录必须由当前用户拥有且不可被 group/world 写入（权限掩码 `& 0022 == 0`），或为受控 root sticky 目录（如 `/tmp`）。
- 目标路径若已存在，直接报错拒绝，绝不覆盖已有文件。
- 写入时先在目标同目录下创建随机命名的隐藏临时文件（权限 `0600`）。
- 写入完成后利用硬链接（`os.Link`）实现原子提交，一旦目标存在则立即失败回滚。
- 如遇上下文取消（Context Cancel）或校验失败，清理过程自动删除临时文件，保持工作区干净。
- 制品生成后**无条件强制调用** `VerifyHostBundle` 执行临时自验，不允许任何跳过选项。

---

## 4. 规范文件格式说明

### 4.1 发布元数据规范（Release Spec）

用于 `build` 子命令的 JSON 规范文件。

#### 示例 1：macOS arm64，后端未变更（unchanged）

```json
{
  "schema_version": 1,
  "product": "acornfox",
  "kind": "host-update-v1",
  "os": "darwin",
  "arch": "arm64",
  "version": "1.2.0",
  "launcher": "launcher/AcornFox",
  "controller": "controller/acornfox-host-update",
  "backend": {
    "mode": "unchanged",
    "binding": "4a5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899"
  }
}
```

#### 示例 2：Linux amd64，后端升级（candidate）

```json
{
  "schema_version": 1,
  "product": "acornfox",
  "kind": "host-update-v1",
  "os": "linux",
  "arch": "amd64",
  "version": "1.2.0",
  "launcher": "launcher/acornfox",
  "controller": "controller/acornfox-host-update",
  "backend": {
    "mode": "candidate",
    "from_binding": "4a5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899",
    "to_binding": "5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899aa",
    "helper_sha256": "6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899aabb"
  }
}
```

注：若在 Spec 中显式提供 `files` 数组，工具将严格核对载荷树中的实际文件是否与其逐一吻合（哈希、大小、权限、无额外文件）；若省略 `files`，工具将自动扫描载荷树并生成有序清单。

### 4.2 索引规范（Index Spec）

用于 `sign-index` 子命令的输入文件，对应 `IndexPayload` 结构（每个 artifact 必须具有非空合法的 `backend_binding`）：

```json
{
  "channel": "stable",
  "sequence": 10,
  "expires_at": "2026-10-01T00:00:00Z",
  "version": "1.2.0",
  "artifacts": [
    {
      "os": "darwin",
      "arch": "arm64",
      "url": "https://downloads.acornfox.com/v1.2.0/acornfox-1.2.0-darwin-arm64.tar.gz",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 15420310,
      "backend_binding": "4a5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899"
    },
    {
      "os": "linux",
      "arch": "amd64",
      "url": "https://downloads.acornfox.com/v1.2.0/acornfox-1.2.0-linux-amd64.tar.gz",
      "sha256": "f4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afb",
      "size": 28410294,
      "backend_binding": "5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899aa"
    },
    {
      "os": "linux",
      "arch": "arm64",
      "url": "https://downloads.acornfox.com/v1.2.0/acornfox-1.2.0-linux-arm64.tar.gz",
      "sha256": "ca495991b7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934",
      "size": 27103820,
      "backend_binding": "5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899aa"
    }
  ]
}
```

---

## 5. 密钥管理与安全控制

1. **私钥格式**：采用标准 PKCS#8 PEM 格式：
   ```text
   -----BEGIN PRIVATE KEY-----
   MC4CAQAwBQYDK2VwBCIEI...
   -----END PRIVATE KEY-----
   ```
2. **私钥文件安全与载荷隔离**：
   - 必须是普通文件，权限严格限制为 `0600`。
   - 所有者必须为当前执行用户（`uid == getuid()`）。
   - 必须显式通过 `--payload-roots` 校验私钥位于所有载荷树（payload roots）与输出目录（output tree）之外。
   - 严禁通过命令行参数（argv）、环境变量、日志或输出回显私钥或种子内容。
   - 内存中的私钥缓冲区在签名完成后立即清零（zeroed）。
3. **生产密钥隔离**：
   - 本工具及仓库中严禁存放任何生产私钥。
   - 单元测试仅在临时目录中就地生成临时测试密钥。
   - 签名收据（Sign Receipt）仅输出公钥十六进制值（`public_key_hex`）和 SHA-256 指纹（`public_key_fingerprint`）。

---

## 6. CLI 使用命令参考

### 6.1 构建宿主制品 (`build`)

```bash
acornfox-host-release build \
  --spec /path/to/spec.json \
  --payload-dir /path/to/payload \
  --output /path/to/acornfox-1.2.0-darwin-arm64.tar.gz
```

输出构建收据示例：
```json
{
  "artifact": "/path/to/acornfox-1.2.0-darwin-arm64.tar.gz",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "size": 15420310,
  "os": "darwin",
  "arch": "arm64",
  "version": "1.2.0",
  "backend_mode": "unchanged",
  "backend_binding": "4a5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899",
  "verified": true
}
```

### 6.2 签名索引文件 (`sign-index`)

必须显式提供操作员信任策略（`--allowed-channel`、`--allowed-hosts`）、实际制品列表（`--bundles`）与载荷根（`--payload-roots`），禁止自待签内容自推规则：

```bash
acornfox-host-release sign-index \
  --index-spec /path/to/index-spec.json \
  --key-file /path/to/release-key.pem \
  --output /path/to/index.json \
  --allowed-channel stable \
  --allowed-hosts downloads.acornfox.com \
  --bundles /path/to/acornfox-1.2.0-darwin-arm64.tar.gz,/path/to/acornfox-1.2.0-linux-amd64.tar.gz \
  --payload-roots /path/to/darwin-payload,/path/to/linux-payload
```

输出签名收据示例：
```json
{
  "output": "/path/to/index.json",
  "schema_version": 1,
  "channel": "stable",
  "sequence": 10,
  "version": "1.2.0",
  "expires_at": "2026-10-01T00:00:00Z",
  "public_key_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "public_key_fingerprint": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "artifacts_count": 2,
  "verified_bundles": [
    {
      "os": "darwin",
      "arch": "arm64",
      "bundle_path": "/path/to/acornfox-1.2.0-darwin-arm64.tar.gz",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 15420310,
      "backend_binding": "4a5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899",
      "verified": true
    }
  ]
}
```

### 6.3 离线验证制品与信封 (`verify-bundle`)

```bash
acornfox-host-release verify-bundle \
  --bundle /path/to/acornfox-1.2.0-darwin-arm64.tar.gz \
  --envelope /path/to/index.json \
  --public-key-hex d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a \
  --os darwin \
  --arch arm64 \
  --channel stable \
  --allowed-hosts downloads.acornfox.com
```

---

## 7. 生产发布标准作业程序（SOP：制品优先，校验随后，原子发布）

按安全发布规范，严禁在制品未就绪前发布索引：

1. **构建各平台制品**：分别执行 `build` 生成各目标架构的 `.tar.gz` 制品（已强制内置 `VerifyHostBundle` 本地验签）。
2. **准备索引规范与离线签名**：在专用离线签名机上提供显式策略参数，执行 `sign-index` 对各真实制品完成全量 `VerifyHostBundle` 验签闭环并生成 `index.json`。
3. **独立复验**：使用 `verify-bundle` 和最终公钥 hex 在独立终端逐一复验各平台制品与已签名 `index.json`。
4. **上传不可变制品**：将各平台制品上传至 CDN 或对象存储（如 `https://downloads.acornfox.com/v1.2.0/...`）。
5. **网络回读核验**：通过网络回读已上传制品的实际大小与 SHA-256，核对与本地构建收据及已签名索引完全一致。
6. **原子发布索引**：将 `index.json` 原子发布到各宿主策略指定的 `HostPolicy.IndexURL`。
