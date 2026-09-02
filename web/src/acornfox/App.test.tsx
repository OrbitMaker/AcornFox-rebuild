import { renderToStaticMarkup } from "react-dom/server";
import AcornFoxApp, { Login } from "./App";
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
  sources: async () => [],
  source: async () => ({
    id: "s",
    application_id: "a",
    kind: "public_git",
    locator_sha256: "",
    content_digest: "",
    created_at: "",
    immutable: true,
  }),
  deployments: async () => [],
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
  it("renders the login as a labelled, password-only entry", () => {
    const html = renderToStaticMarkup(
      <Login api={api} onReady={() => undefined} />,
    );
    expect(html).toContain("登录管理台");
    expect(html).toContain("管理员密码");
    expect(html).toContain("current-password");
  });
  it("renders only the first-version operational navigation", () => {
    const html = renderToStaticMarkup(
      <AcornFoxApp api={api} initialAuthenticated />,
    );
    for (const text of [
      "AcornFox",
      "应用列表",
      "创建应用",
      "公开 HTTPS Git 地址",
      "应用工作区",
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
});
