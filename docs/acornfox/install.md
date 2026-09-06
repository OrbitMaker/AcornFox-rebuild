# 在专用服务器上安装 AcornFox

本文适用于 `v0.1.0-beta.1` 的 Ubuntu 24.04 amd64 安装包。命令在服务器的 **root Bash 终端**执行。示例域名 `console.example.com` 需要替换成你的域名。

## 1. 准备服务器和域名

使用独立的 Ubuntu 24.04 x86_64 服务器，systemd 必须处于 `running` 状态。安装器会安装系统软件包、创建专用服务账号、配置数据库和容器网络，并使用 `/opt/acornfox`、`/etc/acornfox`、`/var/lib/acornfox` 与 `/var/log/acornfox`。请使用未安装 AcornFox、没有需要共存业务的宿主。

安装和构建需要访问 Ubuntu 软件源、公开 Git 仓库、镜像仓库及公共 DNS；签发 HTTPS 证书还需要访问证书颁发服务。系统时间应准确。

在域名服务商处创建两条 A 记录，均指向本机公网 IPv4：

| 记录 | 用途 |
| --- | --- |
| `console.example.com` | 网页控制台 |
| `*.apps.console.example.com` | 应用的自动分配域名 |

云安全组和宿主防火墙允许公网 TCP 80、443，SSH 端口只允许你的管理入口访问。80 用于证书验证及 HTTPS 跳转，443 用于控制台和应用。不要把回环监听的数据库、Docker、控制接口和代理管理端口对外开放。域名有 AAAA 记录时，还必须具备相应的 IPv6 连通性；本指南使用 IPv4。

```bash
sudo -i
bash
set -euo pipefail
umask 077
uname -m
systemctl is-system-running
getent ahostsv4 console.example.com
getent ahostsv4 probe.apps.console.example.com
```

前两个结果应分别为 `x86_64`、`running`；两个域名应解析到目标服务器。若 systemd 报 `degraded`，先用 `systemctl --failed` 排查失败服务。

## 2. 下载并核对发布文件

从 [v0.1.0-beta.1 发布页面](https://github.com/EleJiuDeiChi/acornfox/releases/tag/v0.1.0-beta.1)取得以下 **六个文件**，保存到服务器 `/root/acornfox-download/v0.1.0-beta.1`。该目录只放这六个普通文件，不放子目录、符号链接或额外说明文件。

```text
candidate-binding.json
candidate-binding.sha256
release-manifest.json
bundle-manifest.sha256
build-record.json
acornfox-0.1.0-beta.1-production.tar.gz
```

先建立目录，再下载或传入文件。目录和文件由 root 所有，不允许其他用户写入。下面的验证程序会将普通候选文件设为安装器要求的 `0644`；外层私有目录保持 `0700`：

```bash
install -d -m 0700 /root/acornfox-download
install -d -m 0700 /root/acornfox-download/v0.1.0-beta.1
```

**可信起点是发布说明中独立公布的 binding SHA-256。** 同目录的 `candidate-binding.sha256` 只能用于对照，不能自行证明下载来源可信。以下命令会校验 binding、manifest、归档及安装入口的摘要，仅提取固定的安装入口，不解压整个归档到宿主。

需要系统的 `python3`；如果未安装，先执行 `apt-get update && apt-get install -y python3`。

```bash
candidate=/root/acornfox-download/v0.1.0-beta.1
helpers=/root/acornfox-bootstrap/v0.1.0-beta.1
read -r -p '粘贴发布说明中的 binding SHA-256: ' binding_sha256
export candidate helpers binding_sha256
python3 <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import tarfile

candidate = pathlib.Path(os.environ['candidate'])
helpers = pathlib.Path(os.environ['helpers'])
expected = os.environ['binding_sha256']

def require(condition, message):
    if not condition:
        raise SystemExit(message)

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

require(re.fullmatch(r'[0-9a-f]{64}', expected), 'binding 摘要格式不正确')
require(not candidate.is_symlink(), '候选目录不能是符号链接')
info = candidate.stat()
require(info.st_uid == 0 and info.st_gid == 0 and
        stat.S_ISDIR(info.st_mode) and info.st_mode & 0o022 == 0,
        '候选目录所有者或权限不正确')
archive_name = 'acornfox-0.1.0-beta.1-production.tar.gz'
names = {'candidate-binding.json', 'candidate-binding.sha256',
         'release-manifest.json', 'bundle-manifest.sha256',
         'build-record.json', archive_name}
require({p.name for p in candidate.iterdir()} == names, '候选文件集合不完整或含额外文件')
for name in names:
    info = (candidate / name).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            info.st_uid == 0 and info.st_gid == 0 and info.st_mode & 0o022 == 0,
            '候选文件所有者、类型或权限不正确')
    (candidate / name).chmod(0o644)
require(digest(candidate / 'candidate-binding.json') == expected, 'binding 摘要不匹配')
require((candidate / 'candidate-binding.sha256').read_bytes() ==
        (expected + '\n').encode(), 'binding 摘要文件不匹配')
binding = json.loads((candidate / 'candidate-binding.json').read_bytes())
require(binding['version'] == '0.1.0-beta.1' and binding['architecture'] == 'amd64',
        '发布版本或架构不匹配')
require(digest(candidate / 'release-manifest.json') == binding['manifest_sha256'],
        'manifest 摘要不匹配')
require(digest(candidate / 'bundle-manifest.sha256') == binding['bundle_manifest_sha256'],
        'bundle manifest 摘要不匹配')
archive = candidate / archive_name
require(digest(archive) == binding['archive_sha256'], '归档摘要不匹配')
manifest = json.loads((candidate / 'release-manifest.json').read_bytes())
index = {entry['path']: entry for entry in manifest['files']}
required = ['bin/acornfox-upgrade', 'scripts/acornfox/install-host.sh',
            'scripts/acornfox/install.sh', 'scripts/acornfox/host-preflight.sh',
            'scripts/acornfox/control-plane-migrate.sh']
require(not helpers.exists() and not helpers.is_symlink(), '提取目标已存在，请保留并检查')
helpers.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
helpers.mkdir(mode=0o700)
with tarfile.open(archive, 'r:gz') as bundle:
    members = bundle.getmembers()
    for path in required:
        matches = [m for m in members if m.name == 'release/' + path]
        require(len(matches) == 1 and matches[0].isfile(), '安装入口类型或数量不正确')
        body = bundle.extractfile(matches[0]).read()
        require(hashlib.sha256(body).hexdigest() == index[path]['sha256'],
                '安装入口摘要不匹配')
        target = helpers / pathlib.Path(path).name
        with target.open('xb') as output:
            output.write(body)
        target.chmod(0o755)
print('固定安装入口校验完成')
PY
helper_sha256=$(sha256sum "$helpers/acornfox-upgrade")
helper_sha256=${helper_sha256%% *}
```

这一步不等于宿主验收。接下来，已校验的安装 helper 还会检查完整候选集合、发布身份、文件清单及宿主状态。不应跳过其检查或手工替换系统中的二进制。

## 3. 安装服务

把 `ACORNFOX_PUBLIC_ORIGIN` 改成已经准备好的 HTTPS 控制台地址。`ACORNFOX_GIT_RESOLVERS` 为宿主可访问的公共 DNS IPv4 地址及端口，以下使用 `1.1.1.1`、`8.8.8.8`；请按服务器所在网络选择实际可用的公共 DNS。

在上一步的同一个 root Bash 终端执行：

```bash
export ACORNFOX_INSTALL_CONFIRMATION=ACORNFOX-INSTALL
export ACORNFOX_DEDICATED_HOST_CONFIRMATION=ACORNFOX-DEDICATED-HOST
export ACORNFOX_PUBLIC_ORIGIN=https://console.example.com
export ACORNFOX_GIT_RESOLVERS=1.1.1.1:53,8.8.8.8:53
"$helpers/install-host.sh" \
  --candidate-dir "$candidate" \
  --binding-sha256 "$binding_sha256" \
  --bootstrap-helper "$helpers/acornfox-upgrade" \
  --bootstrap-helper-sha256 "$helper_sha256"
```

安装完成会输出含 `"code":"installed"` 和 `"ok":true` 的回执。安装失败时保留候选包、安装输出和已有安装目录，先诊断明确的失败点；不要删除安装日志、手动修改 `current` 链接或覆盖配置来跳过恢复流程。

## 4. 创建管理员并登录

管理员密码只通过 root 所有、权限 `0600` 的普通文件传给初始化工具。以下从终端隐藏读取密码，不把密码放进命令参数、环境变量或 shell 历史。使用至少 15 个字符的密码，并保存到自己的密码管理器。

```bash
install -d -m 0700 /root/acornfox-secrets
password_file=/root/acornfox-secrets/admin-password
[ ! -e "$password_file" ] && [ ! -L "$password_file" ]
read -r -s -p '设置管理员密码（至少 15 个字符）: ' admin_password
printf '\n'
(umask 077; set -o noclobber; printf '%s\n' "$admin_password" > "$password_file")
unset admin_password
chmod 0600 "$password_file"
/opt/acornfox/current/bin/acornfox-admin bootstrap --password-file "$password_file"
```

打开 `https://console.example.com`，使用刚设置的管理员密码登录。初始化只用于首次创建；已有管理员时，宿主上的密码恢复入口为 `acornfox-admin reset-password --password-file ABSOLUTE_PATH`，对密码文件的要求相同。

## 5. 部署第一个应用并检查真实访问

准备一个仓库根目录含普通 `Dockerfile` 的公开 Git 项目。首版按这个 Dockerfile 构建，不自动把任意源码转换成可运行镜像；Compose、私有仓库和嵌套 Dockerfile 不属于本文流程。

网页中导入仓库，选择源码版本、指定应用监听端口并部署。项目中的应用需要监听容器内 `0.0.0.0`，不能仅监听容器自己的回环地址。

也可以使用已安装的 CLI。下面的仓库和端口仅为示例，请替换成自己的公开仓库、Git ref 和实际端口：

```bash
acornfox=/opt/acornfox/current/bin/acornfox
"$acornfox" login --server https://console.example.com
"$acornfox" apps create --name hello \
  --repository https://github.com/OWNER/REPOSITORY.git --ref main
```

命令返回应用和源码信息。将返回值填入后续命令，不要使用名称代替 ID：

```bash
read -r -p '应用 ID: ' app_id
read -r -p '源码 ID: ' source_id
"$acornfox" deploy "$app_id" --source "$source_id" --port 8080
read -r -p '部署 ID: ' deployment_id
"$acornfox" status "$app_id" "$deployment_id"
"$acornfox" logs "$app_id" "$deployment_id" --source build
"$acornfox" logs "$app_id" "$deployment_id" --source runtime
"$acornfox" public-access enable "$app_id" "$deployment_id"
"$acornfox" public-access get "$app_id" "$deployment_id"
```

公网地址形如 `https://delivery-….apps.console.example.com`。启用后，从服务器之外的浏览器打开返回的**完整地址**，确认 HTTPS 证书有效、页面内容正确，再执行应用的关键操作。首次访问可能需要等待证书签发。构建成功、容器处于运行状态和宿主健康检查通过，分别只证明各自环节；它们不能替代这次公网访问检查。

需要关闭入口时运行：

```bash
"$acornfox" public-access disable "$app_id" "$deployment_id"
```

## 6. 日常检查与后续升级

```bash
systemctl --failed
systemctl status acornfox-server.service acornfox-agent.service acornfox-edge.service --no-pager
systemctl start acornfox-healthcheck.service
journalctl -u acornfox-healthcheck.service -n 30 --no-pager
journalctl -u acornfox-server.service -u acornfox-agent.service -u acornfox-edge.service -n 100 --no-pager
```

健康检查检查本机服务，不会替你完成公网应用验收。分享日志前应删去私密信息，不要上传整个 `/etc/acornfox` 或 `/var/lib/acornfox`。

后续升级必须使用发布说明明确支持当前版本的**后继包**；不能拿首次安装包代替升级包。保存当前版本的可信 binding SHA-256，并按后继版本发布说明校验及提取其 `acornfox-upgrade` 与 `scripts/acornfox/upgrade.sh`。升级入口使用的是新包中的 helper：

```bash
# 将以下变量设为已校验的后继包、独立提取的入口和可信摘要。
# next_candidate、next_helpers 均为 root 所有的绝对路径。
"$next_helpers/upgrade.sh" \
  --candidate-dir "$next_candidate" \
  --next-binding-sha256 "$next_binding_sha256" \
  --current-binding-sha256 "$current_binding_sha256" \
  --successor-helper "$next_helpers/acornfox-upgrade" \
  --successor-helper-sha256 "$successor_helper_sha256"
```

升级前保存可恢复的数据备份，并安排控制台和公网入口的维护时间。保留旧版本与事务记录，不要手工删除 `/var/lib/acornfox/upgrade-in-progress`。升级后重新检查管理员登录、原有应用和公网 HTTPS 响应。支持的前驱版本、数据兼容条件和恢复限制以该次升级的发布说明为准。
