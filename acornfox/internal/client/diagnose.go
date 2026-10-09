package client

import "strings"

// connect stage codes (docs/n2-contract.md section 1 table).
const (
	codeSSHMissing       = "ssh_missing"
	codeHostUnreachable  = "host_unreachable"
	codeAuthFailed       = "auth_failed"
	codeHostKeyUnknown   = "host_key_unknown"
	codeHostKeyChanged   = "host_key_changed"
	codeAcornfoxMissing  = "acornfox_missing"
	codePermissionDenied = "permission_denied"
	codeServerDown       = "server_down"
	codeVersionMismatch  = "version_mismatch"
	codeForwardingOff    = "forwarding_disabled"
	codeConnectFailed    = "connect_failed"
)

// stageConnect is the diagnosis stage for every failure that happens before we
// receive any HTTP response bytes from the server.
const stageConnect = "connect"

// proxy exit codes returned by `acornfox proxy` (contract section 1).
const (
	proxyExitPermissionDenied = 13 // socket connect refused by permissions
	proxyExitServerDown       = 14 // socket missing / server not running
)

// connectError builds a connect-stage *Error with the given code, a Chinese
// message and the matching hint from the contract table. The captured ssh
// stderr (already bounded) is attached as LogExcerpt.
func connectError(code, stderr string) *Error {
	msg, hint := connectMessage(code)
	return &Error{
		Status: 0,
		Diag: Diagnosis{
			Stage:      stageConnect,
			Code:       code,
			Message:    msg,
			Hint:       hint,
			LogExcerpt: strings.TrimSpace(stderr),
		},
	}
}

// connectMessage returns the Chinese message and hint for a connect code.
func connectMessage(code string) (message, hint string) {
	switch code {
	case codeSSHMissing:
		return "本机找不到 ssh 命令", "安装 OpenSSH 客户端（Windows：设置 → 可选功能）"
	case codeHostUnreachable:
		return "无法连接到服务器", "检查地址、端口、安全组是否放行 22"
	case codeAuthFailed:
		return "SSH 认证失败", "先在终端里 `ssh user@host` 确认能免密登录（`ssh-copy-id`）"
	case codeHostKeyUnknown:
		return "服务器主机指纹未确认", "先手动 `ssh user@host` 一次确认主机指纹"
	case codeHostKeyChanged:
		return "服务器主机指纹与本机记录不一致", "若确认服务器重装过或 IP 换了机器，运行 `ssh-keygen -R 主机` 删除旧记录，再手动 `ssh user@host` 确认新指纹；否则可能是中间人攻击，不要继续"
	case codeAcornfoxMissing:
		return "服务器上未安装 acornfox", "服务器上尚未安装 AcornFox"
	case codePermissionDenied:
		return "无权访问 acornfox 服务", "把该用户加入 `acornfox-users` 组后重新登录"
	case codeServerDown:
		return "acornfox 服务未运行", "在服务器上执行 `systemctl status acornfox-server`"
	case codeVersionMismatch:
		return "CLI 与服务器 API 版本不兼容", "升级 CLI 或服务器"
	case codeForwardingOff:
		return "服务器禁止了 SSH 端口转发", "服务器 sshd 需要 `AllowTcpForwarding yes`"
	default:
		return "SSH 连接失败", "先在终端里手动 `ssh user@host` 排查"
	}
}

// classifySSH maps an ssh process's exit code and captured stderr into a
// connect diagnosis code. exitCode is the process exit status (-1 if unknown);
// stderr is the bounded stderr text.
//
// Order matters: proxy-specific exit codes and their stderr banners are checked
// first, then OpenSSH's own diagnostic strings, then generic exit 127.
func classifySSH(exitCode int, stderr string) string {
	low := strings.ToLower(stderr)

	// The `acornfox proxy` process reports socket problems via dedicated exit
	// codes plus a stable banner on stderr.
	switch exitCode {
	case proxyExitPermissionDenied:
		return codePermissionDenied
	case proxyExitServerDown:
		return codeServerDown
	}
	if strings.Contains(low, "acornfox proxy: permission denied") {
		return codePermissionDenied
	}
	if strings.Contains(low, "acornfox proxy: server not running") {
		return codeServerDown
	}

	// OpenSSH client diagnostics.
	switch {
	case strings.Contains(low, "administratively prohibited"),
		strings.Contains(low, "port forwarding is disabled"):
		return codeForwardingOff
	case strings.Contains(low, "could not resolve hostname"),
		strings.Contains(low, "connection refused"),
		strings.Contains(low, "connection timed out"),
		strings.Contains(low, "connection timeout"),
		strings.Contains(low, "operation timed out"),
		strings.Contains(low, "no route to host"),
		strings.Contains(low, "network is unreachable"):
		return codeHostUnreachable
	// A changed key also ends with "Host key verification failed", so check it first.
	case strings.Contains(low, "remote host identification has changed"):
		return codeHostKeyChanged
	case strings.Contains(low, "host key verification failed"):
		return codeHostKeyUnknown
	case strings.Contains(low, "permission denied"):
		return codeAuthFailed
	}

	// Remote command not found: the shell prints "command not found" and exits
	// 127; ssh relays that exit status.
	// The shell message is localized (e.g. zh_CN "未找到命令"), so match the
	// common forms and fall back to the exit status.
	if strings.Contains(low, "command not found") ||
		strings.Contains(low, ": not found") ||
		strings.Contains(stderr, "未找到命令") ||
		strings.Contains(stderr, "找不到命令") ||
		exitCode == 127 {
		return codeAcornfoxMissing
	}

	return codeConnectFailed
}
