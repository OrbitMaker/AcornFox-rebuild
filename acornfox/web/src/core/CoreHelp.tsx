import { isLoopbackOrigin } from "../acornfox/csrf";
import { HelpDialog, useClipboardCopy } from "../shared/HelpDialog";

export interface CoreHelpProps {
  open: boolean;
  onClose: () => void;
  onToast?: (message: string) => void;
}

export function formatCoreLoginCommand(browserOrigin?: string): string {
  const originStr =
    browserOrigin && browserOrigin.trim() !== "" ? browserOrigin.trim() : "";
  if (originStr) {
    if (isLoopbackOrigin(originStr)) {
      return `acornfox login --local --server ${originStr}`;
    }
    try {
      const url = new URL(originStr);
      if (url.protocol === "https:") {
        return `acornfox login --server ${url.origin}`;
      }
    } catch {
      /* ignore invalid URL format */
    }
    return "# 公网 HTTP 不支持明文凭据登录；请通过 HTTPS 执行：\nacornfox login --server HTTPS_ORIGIN";
  }
  return "acornfox login --local --server http://127.0.0.1:PORT";
}

export function formatCoreCliHelp(browserOrigin?: string): string {
  const loginCmd = formatCoreLoginCommand(browserOrigin);

  return `# AcornFox 核心控制面 CLI 指令（已支持）：

# 1. 登录控制台（指定本地 loopback 或受信 HTTPS 地址）
${loginCmd}

# 2. 检查当前管理员会话状态
acornfox session

# 3. 修改管理员密码
acornfox password change

# 4. 退出登录并清除本地会话
acornfox logout

# 5. 查看宿主机器指标当前采样
acornfox host metrics

# 6. 查看宿主机器近30分钟历史指标
acornfox host recent [--limit N]

# 离线恢复说明：
# 核心原型暂未提供离线恢复入口；如遗忘管理员凭据，需要主机运维人员处理。`;
}

export function CoreHelp({ open, onClose, onToast }: CoreHelpProps) {
  const { copiedKey, fallbackText, copy } = useClipboardCopy(onToast);
  const browserOrigin =
    typeof window !== "undefined" ? window.location?.origin : undefined;
  const loginCmd = formatCoreLoginCommand(browserOrigin);
  const fullHelp = formatCoreCliHelp(browserOrigin);

  return (
    <HelpDialog
      open={open}
      title="外部 AI 协作（薄核心控制面）"
      notice={
        <>
          <strong>单机版外部 AI 规范：</strong>
          系统已退出内置模型与聊天窗口。当前运行于单机薄核心模式，可通过外部 AI
          客户端（如 Claude Code / Codex / Cursor）结合标准 AcornFox 核心 CLI
          进行控制面维护与会话管理。所有命令均需在终端受控执行。
        </>
      }
      fallbackText={fallbackText}
      onClose={onClose}
    >
      <section
        className="external-ai-help-section"
        aria-labelledby="core-cli-section-title"
      >
        <div className="external-ai-help-section-header">
          <div
            className="external-ai-help-section-title"
            id="core-cli-section-title"
          >
            <span>AcornFox 核心控制面 CLI 指令</span>
            <span className="af-badge">真实支持</span>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button
              type="button"
              className={`external-ai-help-copy-btn ${copiedKey === "login" ? "is-copied" : ""}`}
              onClick={() => copy(loginCmd, "login", "登录指令")}
            >
              {copiedKey === "login" ? "已复制 ✓" : "复制 login"}
            </button>
            <button
              type="button"
              className={`external-ai-help-copy-btn ${copiedKey === "session" ? "is-copied" : ""}`}
              onClick={() => copy("acornfox session", "session", "会话检查指令")}
            >
              {copiedKey === "session" ? "已复制 ✓" : "复制 session"}
            </button>
            <button
              type="button"
              className={`external-ai-help-copy-btn ${copiedKey === "full" ? "is-copied" : ""}`}
              onClick={() => copy(fullHelp, "full", "核心 CLI 命令")}
            >
              {copiedKey === "full" ? "已复制 ✓" : "复制完整指令"}
            </button>
          </div>
        </div>
        <div className="external-ai-help-section-sub">
          以下为当前核心与 CLI 已支持的指令，不包含未安装功能包的计划命令：
        </div>
        <div className="external-ai-help-code-container">
          <pre className="external-ai-help-pre">
            <code>{fullHelp}</code>
          </pre>
        </div>
      </section>
    </HelpDialog>
  );
}
