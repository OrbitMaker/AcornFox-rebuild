# 用自己的 AI 和 AcornFox 部署项目

AcornFox 负责接收项目、生成镜像并运行容器。你的 AI 客户端负责阅读项目、补齐 Dockerfile 和运行配置。CLI 调用平台 API，不直接操作数据库或 Docker，也不会替你重写业务代码。

运行 `acornfox help --json` 查看当前 CLI 提供的命令。安装、升级请使用与 CLI 配套的发布物；参见[安装说明](install.md)。

## 登录

远程管理使用 HTTPS。以下命令会在终端提示输入密码，不要把密码放进命令参数：

```sh
acornfox login --server https://console.example.com
```

如果 AI 就在服务器本机运行，可以使用安装输出里的回环地址：

```sh
acornfox login --local --server http://127.0.0.1:PORT
```

将 `PORT` 换成实际控制台端口。`--local` 仅允许回环 IP 的 HTTP，不允许公网或局域网 HTTP 降级。自动化可使用 `--password-stdin` 从安全输入读取一行密码；不要把密码、会话文件或密钥贴进对话、脚本日志或项目仓库。

## 先检查本地项目

```sh
acornfox check ./my-project --json
```

- `ready_for_upload`：文件符合上传要求，存在根目录 Dockerfile；这不代表应用已部署。
- `configuration_required`：让自己的 AI 根据 `issues` 补齐配置，再检查一次。
- 依赖缓存、版本库目录和常见凭据文件会被排除；`excluded_paths` 会列出排除项。
- 不跟随项目内符号链接。单文件最多 32 MiB，合计最多 100 MiB、10,000 个文件；服务器还会独立检查。
- 当前上传路径仅支持 ASCII 文件名。不要自动改动用户文件；不兼容的路径先由项目所有者决定如何调整。

## 运行配置

需要覆盖镜像默认启动方式、声明数据目录或调整资源时，创建 `runtime.json`。例如：

```json
{
  "environment": [{"name": "APP_MODE", "value": "production"}],
  "volumes": [{"name": "data", "mount_path": "/app/data", "size_bytes": 67108864}],
  "resources": {
    "cpu_millis": 500,
    "memory_bytes": 536870912,
    "pids": 128,
    "disk_reservation_bytes": 268435456
  }
}
```

数据目录必须换成应用实际使用的位置。`name` 标识同一个应用的数据卷，更新时保持名称和目录稳定。磁盘数字是容量预留，不是 Docker 本地卷的硬配额。需要时可以增加 `entrypoint`、`command` 字符串数组；省略时沿用镜像默认值。

普通参数和环境变量会随版本保存，不能填写密码或令牌。当前入口明确不支持运行期 secret 文件；应用内部的登录与业务设置由用户自己的 AI 后续维护。不要用明文参数绕过限制。

```sh
acornfox check ./my-project --runtime-file runtime.json --json
```

## 上传、查看计划、部署

一步提交本地项目：

```sh
acornfox up ./my-project --name my-app --runtime-file runtime.json --json
```

也可以先只上传并查看服务器识别出的配置：

```sh
acornfox up ./my-project --name my-app --no-deploy --json
acornfox plan APP_ID SOURCE_ID --json
```

保存返回的 `application.id`、`source_revision_id`。如果根目录没有 Dockerfile，或者无法唯一确定端口，AI 应补齐配置后再提交。端口不能推断时由用户或 AI 根据实际启动配置明确选择 `--port PORT`。

修改后继续使用同一个应用：

```sh
acornfox up ./my-project --app APP_ID --base-source SOURCE_ID --runtime-file runtime.json --port 8080 --json
```

也可拆开操作：

```sh
acornfox sources upload APP_ID SOURCE_ID ./my-project --json
acornfox plan APP_ID NEW_SOURCE_ID --json
acornfox deploy APP_ID --source NEW_SOURCE_ID --runtime-file runtime.json --port 8080 --json
```

相同内容会复用已验证的来源。需要重试同一网络操作时，可重复使用同一个 `--idempotency-key KEY`；修改了输入后要使用新 key。只改运行参数时，可直接使用已有 SOURCE_ID 重新提交部署，无须重复上传。

GitHub 项目仍使用公开 HTTPS 仓库地址：

```sh
acornfox up https://github.com/OWNER/REPOSITORY.git --ref main --json
```

## 判断结果和处理失败

`accepted: true` 只表示服务器接受了部署请求。CLI 不把它写成“应用已运行”。继续读取真实状态与日志：

```sh
acornfox status APP_ID DEPLOYMENT_ID --json
acornfox operation APP_ID OPERATION_ID --json
acornfox logs APP_ID DEPLOYMENT_ID --source build --json
acornfox logs APP_ID DEPLOYMENT_ID --source runtime --json
```

检查过程中保存应用、来源、部署和操作 ID，按返回的错误与日志定位。不要因为一次失败就反复创建新应用。程序退出码为：0 成功完成命令；2 输入或配置需调整；3 登录问题；4 冲突；5 暂时不可用；6 接口响应不符合约定。

建议交给 AI 的工作范围是：检查项目 → 补齐必要容器配置 → 本地检查 → 上传并读取计划 → 按计划部署 → 查看状态和日志。遇到业务改造、数据迁移或超出原项目范围的工作时，先交回用户决定。
