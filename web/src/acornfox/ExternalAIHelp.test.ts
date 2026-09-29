import { describe, expect, it } from "vitest";
import {
  buildAppTaskData,
  formatAppTaskPrompt,
  normalizedTaskPort,
  formatGeneralCliWorkflow
} from "./ExternalAIHelp";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

describe("ExternalAIHelp command contracts and safety", () => {
  it("formats general CLI workflow without fake create or cd commands", () => {
    const workflow = formatGeneralCliWorkflow();

    // 契约包含帮助、检查、计划推导与部署
    expect(workflow).toContain("acornfox help --json");
    expect(workflow).toContain('acornfox check "PROJECT_DIRECTORY" --json');
    expect(workflow).toContain('acornfox up "PROJECT_DIRECTORY" --name "APP_NAME" --no-deploy --json');
    expect(workflow).toContain("acornfox deploy APP_ID --source SOURCE_ID --port PORT");

    // 不存在不存在的 create 子命令，也不伪造 cd 目录
    expect(workflow).not.toContain("acornfox create");
    expect(workflow).not.toContain("cd /");
    expect(workflow).toContain("占位符");
  });

  it("safely serializes untrusted application names and handles missing deployment id", () => {
    const untrustedApp = {
      id: "app-test-123",
      name: 'Malicious "Name" && rm -rf / ; --help'
    };

    // 1. JSON.stringify 隔离不可信输入
    const taskDataJson = buildAppTaskData(untrustedApp, undefined, undefined, 3000);
    const parsed = JSON.parse(taskDataJson);
    expect(parsed.application_id).toBe("app-test-123");
    expect(parsed.name).toBe('Malicious "Name" && rm -rf / ; --help');
    expect(parsed.deployment_id).toBeNull();
    expect(parsed.container_port).toBe(3000);

    // 2. 格式化任务单，缺少 deploymentId 时必须明显标为占位符，绝不为空字符串
    const prompt = formatAppTaskPrompt(untrustedApp);
    expect(prompt).toContain("<DEPLOYMENT_ID>");
    expect(prompt).not.toContain("acornfox status app-test-123  ");
    expect(prompt).not.toContain("acornfox logs app-test-123  ");

    // 必须包含完整参数和 --source
    expect(prompt).toContain("acornfox deployments list app-test-123 --json");
    expect(prompt).toContain("acornfox status app-test-123 <DEPLOYMENT_ID> --json");
    expect(prompt).toContain("acornfox logs app-test-123 <DEPLOYMENT_ID> --source runtime --json");
    expect(prompt).toContain("acornfox logs app-test-123 <DEPLOYMENT_ID> --source build --json");
    expect(prompt).toContain("acornfox sources list app-test-123 --json");
    expect(prompt).toContain("acornfox deploy app-test-123 --source <SOURCE_ID> --port <PORT>");
  });

  it("injects real deployment and source IDs when available", () => {
    const app = { id: "app-prod-456", name: "商城前台" };
    const prompt = formatAppTaskPrompt(app, "dep-999", "src-888", "8080");

    expect(prompt).toContain("acornfox status app-prod-456 dep-999 --json");
    expect(prompt).toContain("acornfox logs app-prod-456 dep-999 --source runtime --json");
    expect(prompt).toContain("acornfox logs app-prod-456 dep-999 --source build --json");
    expect(prompt).toContain("acornfox deploy app-prod-456 --source src-888 --port 8080");
  });

  it.each([undefined, "", "8080; touch /tmp/unwanted", "0", "65536", "8e3", "2.5"])("rejects an unknown or unsafe port: %s", (port) => {
    expect(normalizedTaskPort(port)).toBeNull();
    const data = JSON.parse(buildAppTaskData({ id: "app_1", name: "Example" }, undefined, undefined, port));
    expect(data.container_port).toBeNull();
    expect(formatAppTaskPrompt({ id: "app_1", name: "Example" }, "dep_1", "src_1", port)).toContain("--port <PORT>");
  });

  it("keeps untrusted identifiers out of executable command lines", () => {
    const prompt = formatAppTaskPrompt({ id: "app; echo unsafe", name: "Example" }, "dep\nunsafe", "src unsafe", 3000);
    const commands = prompt.split("\n").filter((line) => line.trim().startsWith("acornfox ")).join("\n");
    expect(commands).not.toContain("echo unsafe");
    expect(commands).toContain("acornfox deploy <APP_ID> --source <SOURCE_ID> --port 3000");
  });

  it("ensures App.tsx has no regressions of built-in chat or simulator", () => {
    const appTsxPath = fileURLToPath(new URL("./App.tsx", import.meta.url));
    const content = fs.readFileSync(appTsxPath, "utf-8");

    // 不包含内置助手导入与状态
    expect(content).not.toContain('import { Assistant } from "./Assistant"');
    expect(content).not.toContain("const [aiChatOpen, setAiChatOpen]");
    expect(content).not.toContain("assistantScope");
    expect(content).not.toContain("assistantAppNames");

    // 不包含原浮窗容器或模拟器发送
    expect(content).not.toContain("ai-floating-container");
    expect(content).not.toContain("ai-chat-window");
    expect(content).not.toContain("chat-bubble");
    expect(content).not.toContain("chat-send-btn");

    // 包含外部AI帮助组件及对齐的 CLI 说明
    expect(content).toContain("ExternalAIHelp");
    expect(content).toContain("外部AI帮助");
    expect(content).toContain("--source runtime");
  });
});
