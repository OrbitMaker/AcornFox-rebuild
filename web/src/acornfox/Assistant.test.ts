import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { applyAssistantEvents, expireAssistantTranscript, BasicMarkdown, scopeKey, sessionLabel } from "./Assistant";

describe("assistant transcript state", () => {
  it("keeps per-page scope pointers distinct and drops duplicate event cursors", () => {
    expect(scopeKey({ kind: "host" })).toBe("host");
    expect(scopeKey({ kind: "app", appId: "app-a" })).toBe("app:app-a");
    const first = applyAssistantEvents({ cursor: 0, incomplete: false, messages: [], runStates: {} }, [
      { cursor: 2, runId: "r", type: "assistant.delta", occurredAt: "2030-01-01T00:00:00Z", text: "你" },
      { cursor: 1, runId: "r", type: "run.accepted", occurredAt: "2030-01-01T00:00:00Z", text: "问题" },
    ]);
    const repeated = applyAssistantEvents(first, [
      { cursor: 2, runId: "r", type: "assistant.delta", occurredAt: "2030-01-01T00:00:00Z", text: "重复" },
      { cursor: 3, runId: "r", type: "assistant.message", occurredAt: "2030-01-01T00:00:01Z", text: "完整回答" },
      { cursor: 4, runId: "r", type: "run.completed", occurredAt: "2030-01-01T00:00:02Z" },
    ]);
    expect(repeated.cursor).toBe(4);
    expect(repeated.messages).toEqual([{ id: "user:r", role: "user", text: "问题" }, { id: "assistant:r", role: "assistant", text: "完整回答" }, { id: "state:r", role: "system", text: "本轮回答已完成。" }]);
    expect(repeated.runStates.r).toBe("completed");
  });

  it("uses the server session scope for readable labels and terminal outcomes", () => {
    expect(sessionLabel({ sessionId: "asst_session_very_long", scope: { kind: "app", appId: "app-a" }, createdAt: "2030-01-01T00:00:00Z", updatedAt: "2030-01-01T00:00:00Z" }, { "app-a": "支付服务" })).toContain("应用 · 支付服务");
    const failed = applyAssistantEvents({ cursor: 0, incomplete: false, messages: [], runStates: {} }, [{ cursor: 1, runId: "r", type: "run.failed", occurredAt: "2030-01-01T00:00:00Z" }]);
    expect(failed.messages.at(-1)).toMatchObject({ role: "system", text: "本轮运行失败，未得到助手回答。" });
  });

  it("renders the supported markdown subset as escaped React text", () => {
    const html = renderToStaticMarkup(createElement(BasicMarkdown, { text: "## 标题\n\n- **重点** 和 `code`\n\n```\n<script>alert(1)</script>\n```\n<p>不会作为 HTML</p>" }));
    expect(html).toContain("<h4><span>标题</span></h4>");
    expect(html).toContain("<strong>重点</strong>");
    expect(html).toContain("<code>code</code>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("&lt;p&gt;不会作为 HTML&lt;/p&gt;");
    expect(html).not.toContain("<script>");
  });
});

it("does not keep an evicted run active after cursor expiry", () => {
  const expired = expireAssistantTranscript({ cursor: 1, incomplete: false, messages: [], runStates: { old: "running", finished: "completed" } }, 10);
  expect(expired.runStates).toEqual({ old: "unknown", finished: "completed" });
  const resumed = applyAssistantEvents(expired, [{ cursor: 11, runId: "new", type: "assistant.delta", occurredAt: "2030-01-01T00:00:00Z", text: "继续" }]);
  expect(resumed.runStates.new).toBe("running");
  expect(resumed.runStates.old).toBe("unknown");
  const late = applyAssistantEvents(resumed, [{ cursor: 12, runId: "old", type: "assistant.delta", occurredAt: "2030-01-01T00:00:01Z", text: "迟到片段" }]);
  expect(late.runStates.old).toBe("unknown");
  expect(resumed.incomplete).toBe(true);
});
