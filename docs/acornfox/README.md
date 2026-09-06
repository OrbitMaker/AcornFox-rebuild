# AcornFox

AcornFox 把含根目录 `Dockerfile` 的公开 Git 仓库部署到你自己的服务器：导入代码、构建镜像、启动应用，再通过 HTTPS 地址访问。可以在网页控制台操作，也可以使用 `acornfox` 命令行客户端。

首版 `v0.1.0-beta.1` 面向 **Ubuntu 24.04、amd64 的专用单机**。适合个人项目和早期应用试用；高可用集群、多租户生产隔离、容器硬磁盘配额及无人值守故障切换不在首版承诺内。CPU、内存与进程数限制和磁盘用量记账是不同能力。

## 开始使用

准备一台有公网 IPv4 的专用服务器和自己的域名，然后按照[安装指南](https://github.com/EleJiuDeiChi/acornfox/blob/v0.1.0-beta.1/docs/acornfox/install.md)完成安装与管理员初始化。

发布包及其校验值见 [GitHub Releases](https://github.com/EleJiuDeiChi/acornfox/releases)。安装需要一组完整的发布文件；请先核对该版本发布说明中的 binding SHA-256，再运行包内安装程序。仓库中的源码和一个通过编译的二进制，不能替代完整安装包。

需要检查或修改程序时，参阅[对应源码构建指南](https://github.com/EleJiuDeiChi/acornfox/blob/v0.1.0-beta.1/docs/acornfox/build.md)。运行中的登录页和控制台也提供指向实际构建提交的源码链接。

安装后的基本流程：

1. 登录控制台，导入一个公开 Git 仓库并指定分支或标签；导入后保存具体提交。
2. 选择源码版本和应用端口，发起部署。
3. 查看构建日志与运行状态，确认应用已启动。
4. 启用公网访问，打开返回的 HTTPS 地址，验证实际响应。

命令行具有相同的主要入口，例如 `apps create`、`deploy`、`status`、`logs` 和 `public-access enable`。可执行示例在安装指南中。API 定义位于 [`api/openapi/acornfox.yaml`](https://github.com/EleJiuDeiChi/acornfox/blob/v0.1.0-beta.1/api/openapi/acornfox.yaml)。

## 运行与反馈

AcornFox 在宿主上安装 systemd 服务、PostgreSQL、Docker、构建工具及 HTTPS 入口。控制台数据、应用容器和证书需要持久化存储；使用抢占式实例时，实例回收会中断服务，应另行保存需要保留的数据。

遇到问题时，请先记录版本、操作步骤、命令退出码及脱敏后的日志，再提交 [Issue](https://github.com/EleJiuDeiChi/acornfox/issues)。不要附上管理员密码、会话 Cookie、私钥、数据库连接串或整个配置目录。

Copyright AcornFox contributors. 项目采用 [AGPL-3.0-only](https://github.com/EleJiuDeiChi/acornfox/blob/v0.1.0-beta.1/LICENSE)；随包第三方组件的许可说明见发布包中的 `docs/licenses/` 和 `sbom.spdx.json`。
