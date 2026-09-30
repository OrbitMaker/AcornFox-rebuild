# 贡献指南

感谢你考虑为 AcornFox 贡献！

## 行为准则

参与此项目即表示你同意遵守我们的[行为准则](CODE_OF_CONDUCT.md)。

## 如何贡献

### 报告 Bug

在创建 Issue 前，请先搜索是否已有相同问题。

**好的 Bug 报告应包含**：

- 清晰的标题
- 复现步骤
- 预期行为 vs 实际行为
- 环境信息（操作系统、AcornFox 版本）
- 相关日志或截图

**模板**：

```markdown
### 问题描述
简要描述遇到的问题

### 复现步骤
1. 执行命令 `acornfox deploy`
2. 查看状态 `acornfox status`
3. 看到错误...

### 预期行为
应该...

### 实际行为
但是...

### 环境信息
- 操作系统: Ubuntu 22.04
- AcornFox 版本: 0.2.0
- Docker 版本: 24.0.5

### 相关日志
```
粘贴相关日志
```
```

### 提出功能建议

我们欢迎新功能建议！请先创建 Issue 讨论：

- **问题**: 当前缺少什么功能？
- **方案**: 你建议如何实现？
- **用例**: 谁会使用这个功能？如何使用？

### 贡献代码

#### 准备工作

1. **Fork 仓库**

2. **克隆到本地**
   ```bash
   git clone https://github.com/your-username/acornfox.git
   cd acornfox
   ```

3. **创建特性分支**
   ```bash
   git checkout -b feature/my-feature
   ```

#### 开发环境

**环境要求**:
- Go 1.21+
- Docker
- Make (可选)

**安装依赖**:
```bash
cd acornfox
go mod download
```

**编译**:
```bash
go build -o acornfox ./cmd/acornfox
```

**运行测试**:
```bash
go test ./...

# 带竞态检测
go test -race ./...
```

#### 代码规范

**Go 代码**:
- 遵循 Go 官方风格指南
- 使用 `gofmt` 格式化代码
- 通过 `go vet` 检查
- 添加必要的注释

**提交信息**:
- 使用清晰的提交信息
- 第一行简短总结（50 字符内）
- 详细说明在空行后
- 引用相关 Issue: `Fixes #123`

**示例**:
```
Add PostgreSQL addon support

- Implement postgres addon type
- Add connection string generation
- Update documentation

Fixes #45
```

#### 测试

**所有代码变更都需要测试**：

- 新功能: 添加单元测试和集成测试
- Bug 修复: 添加回归测试
- 确保所有测试通过

**运行测试**:
```bash
# 单元测试
go test ./internal/...

# 集成测试
go test ./tests/integration/...

# 覆盖率
go test -cover ./...
```

#### 文档

更新相关文档：

- README.md (如果改变核心功能)
- docs/ 下的具体文档
- 命令行 --help 文本
- 代码注释

#### 提交 Pull Request

1. **推送分支**
   ```bash
   git push origin feature/my-feature
   ```

2. **创建 PR**
   - 在 GitHub 上创建 Pull Request
   - 填写 PR 模板
   - 关联相关 Issue

3. **PR 描述应包含**:
   - 变更摘要
   - 相关 Issue
   - 测试说明
   - 截图（如有 UI 变更）

4. **代码审查**
   - 维护者会审查你的代码
   - 根据反馈进行修改
   - 保持耐心和友善

#### PR 检查清单

在提交 PR 前，确认：

- [ ] 代码遵循项目风格
- [ ] 通过所有测试
- [ ] 添加了必要的测试
- [ ] 更新了文档
- [ ] 提交信息清晰
- [ ] 没有合并冲突
- [ ] 签署了 CLA（如需要）

## 开发流程

### 项目结构

```
acornfox/
├── cmd/acornfox/       # 主程序入口
├── internal/           # 内部包
│   ├── apiserver/      # API 服务器
│   ├── cli/            # CLI 命令
│   ├── client/         # API 客户端
│   ├── runner/         # Docker 执行器
│   ├── reconcile/      # 调和器
│   └── state/          # 状态管理
├── docs/               # 文档
├── scripts/            # 脚本
└── tests/              # 测试
```

### 架构原则

AcornFox 遵循以下设计原则：

1. **状态与执行分离**: server 记录状态，runner 执行操作
2. **调和而非编排**: 记录"应该是"，自动收敛到目标状态
3. **最小权限**: server 无 Docker 权限，只有 runner 能访问 Docker
4. **应用独立**: 应用由 Docker 管理，AcornFox 崩溃不影响运行中应用

### 常见开发任务

#### 添加新命令

1. 在 `internal/cli/` 添加命令处理函数
2. 在 `cli.go` 的 switch 中注册
3. 添加测试
4. 更新文档和 --help 文本

#### 添加新 API

1. 在 `internal/client/` 定义接口
2. 在 `internal/apiserver/` 实现处理器
3. 在 `internal/runner/` 实现执行逻辑（如需要）
4. 添加测试
5. 更新 API 文档

#### 添加新附加服务类型

1. 在 `internal/state/` 添加服务类型定义
2. 在 `internal/runner/` 实现容器创建逻辑
3. 在 `internal/apiserver/` 添加 API 端点
4. 在 `internal/cli/` 添加命令
5. 更新文档

## 发布流程

（仅适用于维护者）

1. 更新版本号
2. 更新 CHANGELOG.md
3. 创建 Git tag
4. 触发 CI/CD 构建
5. 发布到 GitHub Releases
6. 更新官网文档

## 获得帮助

- **文档**: 先查看现有文档
- **Issues**: 搜索类似问题
- **讨论**: GitHub Discussions
- **即时通讯**: （待定）

## 许可证

贡献的代码将在 AGPL-3.0 许可证下发布。

通过提交 Pull Request，你同意你的贡献将在此许可证下发布。

## 致谢

感谢所有贡献者！你的贡献让 AcornFox 变得更好。

---

**有问题？** 创建 Issue 或在 PR 中提问，我们很乐意帮助！🦊
