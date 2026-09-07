import { renderToStaticMarkup } from "react-dom/server";
import AcornFoxApp, { DeliveryWorkspace, hostIsFresh, Login, operationIsTerminal } from "./App";
import type { AcornFoxClient } from "./client";

const api: AcornFoxClient = {
  login: async () => ({
    authenticated: true,
    idle_expires_at: "",
    absolute_expires_at: "",
  }),
  logout: async () => undefined,
  session: async () => ({
    authenticated: true,
    idle_expires_at: "",
    absolute_expires_at: "",
  }),
  changePassword: async () => undefined,
  apps: async () => [],
  app: async () => ({ id: "a", name: "A", created_at: "", updated_at: "" }),
  createApp: async () => ({
    application: { id: "a", name: "A", created_at: "", updated_at: "" },
    sourceRevisionId: "s",
    operationId: "o",
  }),
  sources: async () => ({ items: [] }),
  source: async () => ({
    id: "s",
    application_id: "a",
    kind: "git_https",
    locator_sha256: "",
    content_digest: "",
    created_at: "",
    immutable: true,
  }),
  deployments: async () => ({ items: [] }),
  deploy: async () => ({
    deployment_id: "d",
    operation_id: "o",
    task_id: "t",
    status: "accepted",
  }),
  status: async () => {
    throw new Error("unused");
  },
  logs: async () => {
    throw new Error("unused");
  },
  probe: async () => ({
    deployment_id: "d", operation_id: "o", task_id: "t", status: "accepted",
  }),
  restart: async () => ({
    deployment_id: "d",
    operation_id: "o",
    task_id: "t",
    status: "accepted",
  }),
  redeploy: async () => ({
    deployment_id: "d",
    operation_id: "o",
    task_id: "t",
    status: "accepted",
  }),
  publicAccess: async () => {
    throw new Error("unused");
  },
  setPublicAccess: async () => {
    throw new Error("unused");
  },
};

describe("AcornFox clean entry", () => {
  it("offers an explicit response check without presenting running as responsive", () => {
    const html = renderToStaticMarkup(<DeliveryWorkspace api={api}
      application={{ id: "a", name: "A", created_at: "", updated_at: "" }}
      deployment={{ id: "d", application_id: "a", environment_id: "e", release_id: "r", stage: "starting", created_at: "", updated_at: "" }} />);
    expect(html).toContain("检查应用响应</button>");
    expect(html).toContain("确认响应记录为 responded");
    expect(html).toContain("运行中不等于能响应请求");
    expect(html).not.toContain("HTTP 200");
  });
  it("renders the login as a labelled, password-only entry", () => {
    const html = renderToStaticMarkup(
      <Login api={api} onReady={() => undefined} />,
    );
    expect(html).toContain("登录管理台");
    expect(html).toContain("管理员密码");
    expect(html).toContain("current-password");
  });
  it("renders the compact first-version operational navigation without unsupported product areas", () => {
    const html = renderToStaticMarkup(
      <AcornFoxApp api={api} initialAuthenticated />,
    );
    for (const text of [
      "AcornFox",
      "首页",
      "创建应用",
      "本机资源",
      "运行情况请查看部署详情",
    ])
      expect(html).toContain(text);
    for (const forbidden of [
      "Rollback",
      "Webhook",
      "AI ",
      "数据库",
      "volume",
      "Compose",
      "archive",
      "private Git",
    ])
      expect(html).not.toContain(forbidden);
  });

  it("hides host facts once their server-provided observation expires", () => {
    const now = Date.now();
    expect(hostIsFresh({ schemaVersion: 1, availability: "available", observedAt: new Date(now - 5_000).toISOString(), staleAfterSeconds: 15 })).toBe(true);
    expect(hostIsFresh({ schemaVersion: 1, availability: "available", observedAt: new Date(now - 16_000).toISOString(), staleAfterSeconds: 15 })).toBe(false);
    expect(hostIsFresh({ schemaVersion: 1, availability: "available", staleAfterSeconds: 15 })).toBe(false);
  });

  it("stops operation polling only for verified, failed, and unknown facts", () => {
    expect(operationIsTerminal("accepted")).toBe(false);
    expect(operationIsTerminal("running")).toBe(false);
    expect(operationIsTerminal("verified")).toBe(true);
    expect(operationIsTerminal("failed")).toBe(true);
    expect(operationIsTerminal("unknown")).toBe(true);
  });
});
