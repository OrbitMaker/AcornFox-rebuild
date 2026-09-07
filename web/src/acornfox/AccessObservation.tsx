import { useEffect, useRef, useState } from "react";
import type {
  AccessDNSObservation,
  AccessHTTPSObservation,
  AccessObservation as Fact,
  AccessObservationFact,
  AccessTLSObservation,
  AcornFoxIntegrationClient,
} from "./integration-client";

type Props = {
  client: AcornFoxIntegrationClient;
  applicationId: string;
  deploymentId: string;
};

type ScopedFact = { scope: string; value: Fact };

const failureExplanations: Record<string, string> = {
  dns_no_answer: "DNS 未返回地址。",
  dns_timeout: "DNS 查询超时。",
  dns_lookup_failed: "DNS 查询失败。",
  tls_connect_failed: "TLS 连接失败。",
  tls_name_mismatch: "证书与访问域名不匹配。",
  tls_certificate_invalid: "TLS 证书无效。",
  tls_timeout: "TLS 连接超时。",
  https_timeout: "HTTPS 请求超时。",
  https_transport_failed: "HTTPS 传输失败。",
};

function localTime(value: string): string {
  return new Date(value).toLocaleString();
}

function dnsText(value: AccessDNSObservation): string {
  return value.state === "observed"
    ? `已观测 · ${value.addresses.join(", ")}`
    : `失败 · ${failureExplanations[value.failureCode]}`;
}

function tlsText(value: AccessTLSObservation): string {
  if (value.state === "not_attempted") return "未尝试 · 前一层未通过，未发起 TLS 连接。";
  if (value.state === "failed") return `失败 · ${failureExplanations[value.failureCode]}`;
  return `已观测 · 证书 SHA-256 ${value.certificateSha256}`;
}

function httpsText(value: AccessHTTPSObservation): string {
  if (value.state === "not_attempted") return "未尝试 · 前一层未通过，未发起 HTTPS 请求。";
  if (value.state === "failed") return `失败 · ${failureExplanations[value.failureCode]}`;
  const healthy = value.httpStatus >= 200 && value.httpStatus < 400;
  return `已观测 · HTTP ${value.httpStatus} · ${healthy ? "响应正常" : "响应已到达，但不健康"}`;
}

export function millisecondsUntilAccessObservationExpiry(fact: Fact, now = Date.now()): number | undefined {
  if (fact.availability === "not_observed") return undefined;
  return Math.max(0, Date.parse(fact.observation.expiresAt) - now);
}

export function accessObservationIsCurrent(fact: Fact, now = Date.now()): boolean {
  return fact.availability === "available" && millisecondsUntilAccessObservationExpiry(fact, now)! > 0;
}

export function AccessObservationDetails({ observation }: { observation: AccessObservationFact }) {
  const https = observation.https;
  return <>
    <dl className="af-facts">
      <div><dt>DNS</dt><dd>{dnsText(observation.dns)}</dd></div>
      <div><dt>TLS</dt><dd>{tlsText(observation.tls)}</dd></div>
      <div><dt>HTTPS</dt><dd>{httpsText(https)}</dd></div>
      <div><dt>观测来源</dt><dd>管理员客户端观测</dd></div>
      <div><dt>访问域名</dt><dd>{observation.hostname}</dd></div>
      <div><dt>观测时间</dt><dd>{localTime(observation.observedAt)}</dd></div>
      <div><dt>接收时间</dt><dd>{localTime(observation.receivedAt)}</dd></div>
      <div><dt>到期时间</dt><dd>{localTime(observation.expiresAt)}</dd></div>
    </dl>
    {https.state === "observed" && <p className="af-note">
      响应样本：{https.responseSampleBytes} 字节{https.responseTruncated ? "（已截断）" : ""} · SHA-256 {https.responseSampleSha256}
    </p>}
  </>;
}

export function AccessObservation({ client, applicationId, deploymentId }: Props) {
  const scope = JSON.stringify([applicationId, deploymentId]);
  const [fact, setFact] = useState<ScopedFact>();
  const [message, setMessage] = useState("");
  const [loadingScope, setLoadingScope] = useState<string>();
  const timer = useRef<ReturnType<typeof setTimeout>>();
  const expirySequence = useRef(0);
  const currentScope = useRef(scope);
  const requestSequence = useRef(0);

  const clearExpiryTimer = () => {
    expirySequence.current += 1;
    if (timer.current !== undefined) clearTimeout(timer.current);
    timer.current = undefined;
  };

  const scheduleExpiry = (next: Fact, nextScope: string) => {
    clearExpiryTimer();
    const delay = millisecondsUntilAccessObservationExpiry(next);
    if (delay === undefined || next.availability === "expired") return;
    const expiry = expirySequence.current;
    timer.current = setTimeout(() => {
      if (expiry !== expirySequence.current || currentScope.current !== nextScope) return;
      setFact((current) => current?.scope === nextScope && current.value.availability !== "not_observed"
        ? { scope: nextScope, value: { availability: "expired", observation: current.value.observation } }
        : current);
    }, delay);
  };

  const refresh = async (nextScope = scope) => {
    const request = ++requestSequence.current;
    setLoadingScope(nextScope);
    try {
      let next = await client.accessObservation(applicationId, deploymentId);
      if (request !== requestSequence.current || currentScope.current !== nextScope) return;
      if (next.availability === "available" && millisecondsUntilAccessObservationExpiry(next) === 0) {
        next = { availability: "expired", observation: next.observation };
      }
      setFact({ scope: nextScope, value: next });
      setMessage("");
      scheduleExpiry(next, nextScope);
    } catch (error) {
      if (request !== requestSequence.current || currentScope.current !== nextScope) return;
      setMessage(error instanceof Error ? error.message : "读取外部访问观测失败，请稍后重试。");
    } finally {
      if (request === requestSequence.current && currentScope.current === nextScope) setLoadingScope(undefined);
    }
  };

  useEffect(() => {
    currentScope.current = scope;
    requestSequence.current += 1;
    clearExpiryTimer();
    setFact(undefined);
    setMessage("");
    void refresh(scope);
    return () => {
      requestSequence.current += 1;
      clearExpiryTimer();
    };
  }, [scope]);

  const visibleFact = fact?.scope === scope ? fact.value : undefined;
  const loading = loadingScope === scope && visibleFact === undefined;
  return <section className="af-section">
    <header>
      <h2 style={{ fontSize: 14 }}>外部访问观测</h2>
      <button type="button" className="af-button--quiet" onClick={() => void refresh()}>刷新</button>
    </header>
    <p className="af-note">来源：管理员客户端观测。该事实由外部机器上报，不代表第三方独立监控。</p>
    {loading && <p className="af-note" role="status">正在读取外部访问观测…</p>}
    {visibleFact?.availability === "not_observed" && <p className="af-note">
      尚无外部访问观测。请在外部机器运行 <code>acornfox public-access check APP DEPLOYMENT</code>。
    </p>}
    {visibleFact?.availability === "expired" && <p className="af-note af-note--warn" role="status">
      最近一次外部访问观测已过期；以下内容仅供追溯。
    </p>}
    {visibleFact?.availability !== "not_observed" && visibleFact?.observation &&
      <AccessObservationDetails observation={visibleFact.observation} />}
    {message && <p className="af-note af-note--warn" role="alert">{message}</p>}
  </section>;
}
