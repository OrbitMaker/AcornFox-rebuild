import { renderToStaticMarkup } from "react-dom/server";
import {
  AccessObservationDetails,
  accessObservationIsCurrent,
  millisecondsUntilAccessObservationExpiry,
} from "./AccessObservation";
import type { AccessObservation, AccessObservationFact } from "./integration-client";

const observation: AccessObservationFact = {
  observer: "administrator_client",
  applicationId: "app_1",
  deploymentId: "dep_1",
  hostname: "delivery-x.apps.example.test",
  reportId: "report_1",
  observedAt: "2030-01-01T00:00:00Z",
  dns: { state: "observed", addresses: ["192.0.2.10"] },
  tls: { state: "observed", certificateSha256: `sha256:${"a".repeat(64)}` },
  https: {
    state: "observed",
    httpStatus: 500,
    responseSampleSha256: `sha256:${"b".repeat(64)}`,
    responseSampleBytes: 321,
    responseTruncated: true,
  },
  receivedAt: "2030-01-01T00:00:00Z",
  expiresAt: "2030-01-01T00:05:00Z",
};

describe("AccessObservation", () => {
  it("expires from expires_at at the boundary", () => {
    const fact: AccessObservation = { availability: "available", observation };
    expect(millisecondsUntilAccessObservationExpiry(fact, Date.parse("2030-01-01T00:04:59.999Z"))).toBe(1);
    expect(accessObservationIsCurrent(fact, Date.parse("2030-01-01T00:04:59.999Z"))).toBe(true);
    expect(millisecondsUntilAccessObservationExpiry(fact, Date.parse(observation.expiresAt))).toBe(0);
    expect(accessObservationIsCurrent(fact, Date.parse(observation.expiresAt))).toBe(false);
  });

  it("renders HTTP 500 as an observed but unhealthy response", () => {
    const html = renderToStaticMarkup(<AccessObservationDetails observation={observation} />);
    expect(html).toContain("已观测 · HTTP 500 · 响应已到达，但不健康");
    expect(html).toContain("管理员客户端观测");
    expect(html).toContain("321 字节（已截断）");
    expect(html).not.toContain("HTTPS 请求失败");
  });

  it("renders fixed explanations for failed and skipped layers", () => {
    const failed: AccessObservationFact = {
      ...observation,
      dns: { state: "failed", failureCode: "dns_timeout" },
      tls: { state: "not_attempted" },
      https: { state: "not_attempted" },
    };
    const html = renderToStaticMarkup(<AccessObservationDetails observation={failed} />);
    expect(html).toContain("失败 · DNS 查询超时。");
    expect(html).toContain("未尝试 · 前一层未通过，未发起 TLS 连接。");
    expect(html).toContain("未尝试 · 前一层未通过，未发起 HTTPS 请求。");
  });
});
