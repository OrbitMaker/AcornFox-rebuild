import { RestApiClient, StubApiClient } from './client';

class FakeEventSource {
  private listener?: EventListener;
  closed = false;

  addEventListener(_type: string, listener: EventListener): void {
    this.listener = listener;
  }

  removeEventListener(_type: string, listener: EventListener): void {
    if (this.listener === listener) this.listener = undefined;
  }

  close(): void {
    this.closed = true;
  }

  emit(data: string): void {
    this.listener?.(new MessageEvent('message', { data }));
  }
}

describe('StubApiClient', () => {
  it('uses the same typed create and event contract as the live client', async () => {
    const client = new StubApiClient();
    const created = await client.createApplication({
      name: 'Release Demo',
      source: { kind: 'git', locator: 'https://git.example.invalid/demo.git', ref: 'main' },
    });
    const events: string[] = [];
    const unsubscribe = client.subscribeToPublishEvents(created.operationId, (event) => events.push(event.status));

    await new Promise((resolve) => setTimeout(resolve, 1_800));
    unsubscribe();

    expect(created.application.operationId).toBe(created.operationId);
    expect(events).toEqual(['preparing', 'building', 'deploying', 'succeeded']);
    expect((await client.listApplications()).items[0]?.name).toBe('Release Demo');
  }, 4_000);
});

describe('RestApiClient', () => {
  it('normalizes the current OpenAPI Application response and validates SSE events', async () => {
    const eventSource = new FakeEventSource();
    const requested: Array<{ url: string; method?: string }> = [];
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async (input, init) => {
        requested.push({ url: String(input), method: init?.method });
        if (init?.method === 'POST') {
          return new Response(JSON.stringify({ id: 'app-live', name: 'Live App', created_at: '2026-08-24T00:00:00.000Z', updated_at: '2026-08-24T00:00:00.000Z' }), { status: 201, headers: { 'content-type': 'application/json' } });
        }
        return new Response(JSON.stringify([{ id: 'app-live', name: 'Live App', created_at: '2026-08-24T00:00:00.000Z', updated_at: '2026-08-24T00:00:00.000Z' }]), { status: 200, headers: { 'content-type': 'application/json' } });
      },
      eventSourceFactory: () => eventSource as unknown as EventSource,
    });

    const list = await client.listApplications();
    const created = await client.createApplication({ name: 'Live App', source: { kind: 'git' } });
    const events: string[] = [];
    const unsubscribe = client.subscribeToPublishEvents(created.operationId, (event) => events.push(event.status));
    eventSource.emit(JSON.stringify({ id: 'evt-1', operation_id: created.operationId, application_id: 'app-live', sequence: 1, occurred_at: '2026-08-24T00:00:01.000Z', kind: 'operation.created', status: 'preparing' }));
    eventSource.emit(JSON.stringify({ id: 'bad', operation_id: created.operationId, application_id: 'app-live', sequence: 2, occurred_at: '2026-08-24T00:00:02.000Z', kind: 'unknown', status: 'preparing' }));
    unsubscribe();

    expect(list.items[0]?.source.kind).toBe('git');
    expect(created.operationId).toBe('application:app-live');
    expect(events).toEqual(['preparing']);
    expect(eventSource.closed).toBe(true);
    expect(requested.map((request) => request.url)).toEqual(['/api/v1/applications', '/api/v1/applications']);
  });

  it('returns an explicit unavailable M4 facade until the control plane composes operations facts', async () => {
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async () => new Response(JSON.stringify({ code: 'not_found' }), { status: 404 }),
    });

    await expect(client.getApplicationOperations('app-live')).resolves.toEqual({
      status: 'unavailable',
      message: '运行与运维事实 API 尚未由控制面组合，无法展示或执行 M4 操作。',
    });
    await expect(client.requestApplicationOperation('app-live', { action: 'restart', expectedVersion: 'ops-v1' }, { actor: 'operator-1', role: 'operator' })).resolves.toEqual({
      status: 'unavailable',
      message: '运行与运维操作 API 尚未由控制面组合，未发送操作。',
    });
  });

  it('passes fact version, actor, role and idempotency headers without claiming action success', async () => {
    let request: RequestInit | undefined;
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async (_input, init) => {
        request = init;
        return new Response(JSON.stringify({ operation_id: 'op-queued' }), { status: 202 });
      },
    });

    const result = await client.requestApplicationOperation('app-live', { action: 'restart', targetServiceId: 'api', expectedVersion: 'ops-v9' }, { actor: 'operator-1', role: 'operator' });
    const headers = new Headers(request?.headers);

    expect(result).toEqual({ status: 'accepted', operationId: 'op-queued', message: '控制面已接受操作请求，正在等待新的事实版本。' });
    expect(headers.get('open-card-actor')).toBe('operator-1');
    expect(headers.get('open-card-role')).toBe('operator');
    expect(headers.get('idempotency-key')).toMatch(/^m4-operation:app-live:/);
    expect(request?.body).toBe(JSON.stringify({ action: 'restart', target_service_id: 'api', expected_version: 'ops-v9', reason: 'operator requested restart after reviewing facts ops-v9' }));
  });

  it('normalizes M5 usage facts and only claims operator detail with an operator header', async () => {
    let request: RequestInit | undefined;
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async (_input, init) => {
        request = init;
        return new Response(JSON.stringify({
          version: 'usage-v1', observed_at: '2026-08-25T00:05:00Z', application_id: 'app-live', application_name: 'Live App', ai: 'disabled', anomalies: [],
          services: [{ id: 'app-live:web:rel-1', name: 'web', release_id: 'rel-1', runtime: '300 秒', started_at: '2026-08-25T00:00:00Z', actual: { cpu: { actual: 250, limit: 500, unit: 'mCPU' }, memory: { actual: 64, limit: 128, unit: 'MiB' }, disk: { actual: 10, limit: 20, unit: 'MiB' }, network: { actual: 1024, limit: 0, unit: 'B' } }, average: { cpu: { actual: 200, limit: 500, unit: 'mCPU' }, memory: { actual: 48, limit: 128, unit: 'MiB' }, disk: { actual: 8, limit: 20, unit: 'MiB' }, network: { actual: 512, limit: 0, unit: 'B' } }, peak: { cpu: { actual: 250, limit: 500, unit: 'mCPU' }, memory: { actual: 64, limit: 128, unit: 'MiB' }, disk: { actual: 10, limit: 20, unit: 'MiB' }, network: { actual: 1024, limit: 0, unit: 'B' } }, configured: { cpu: { actual: 500, limit: 500, unit: 'mCPU' }, memory: { actual: 128, limit: 128, unit: 'MiB' }, disk: { actual: 20, limit: 20, unit: 'MiB' }, network: { actual: 0, limit: 0, unit: 'B' } }, anomalies: [], trend: [{ observed_at: '2026-08-25T00:05:00Z', cpu: { actual: 200, limit: 500, unit: 'mCPU' }, memory: { actual: 48, limit: 128, unit: 'MiB' }, disk: { actual: 8, limit: 20, unit: 'MiB' }, network: { actual: 512, limit: 0, unit: 'B' } }] }],
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      },
    });

    const result = await client.getApplicationUsage('app-live', 'operations');
    expect(result.status).toBe('available');
    expect(result.status === 'available' && result.facts.services[0]?.actual.cpu.actual).toBe(250);
    expect(new Headers(request?.headers).get('open-card-role')).toBe('operator');
  });

  it('keeps M6 intervention and settings facts explicit without claiming external AI', async () => {
    const requests: Array<{ url: string; headers: Headers }> = [];
    const client = new RestApiClient({ baseUrl: '/api/v1', fetchImpl: async (input, init) => {
      requests.push({ url: String(input), headers: new Headers(init?.headers) });
      if (String(input).endsWith('/settings/ai')) return new Response(JSON.stringify({ version: 'ai-v1', enabled: false, status: 'disabled', profile: 'disabled', provider: '', model: '', data_scopes: [], max_tokens: 128, max_duration_ms: 1000, cooldown_seconds: 60, cache_enabled: true, external_calls: false }), { status: 200 });
      return new Response(JSON.stringify({ version: 'ai-v1', mode: 'operator', ai_status: 'available', success_count: 0, failure_count: 1, rollback_count: 1, candidate_count: 0, total_tokens: 12, total_duration_ms: 20, items: [{ id: 'airec-1', application_id: 'app-live', task_type: 'build_failure_diagnosis', status: 'rolled_back', reason: 'rule miss', summary: 'verification failed', suggestion: 'review candidate', requires_user_action: true, controller_handoff: false, evidence: [], tokens: 12, duration_ms: 20, rolled_back: true, created_at: '2026-08-25T00:00:00Z' }] }), { status: 200 });
    } });
    const interventions = await client.getAIInterventions('app-live', 'operator');
    const settings = await client.getAISettings();
    expect(interventions.status === 'available' && interventions.facts.items[0]?.status).toBe('rolled_back');
    expect(settings.status === 'available' && settings.settings.externalCalls).toBe(false);
    expect(requests[0]?.headers.get('open-card-role')).toBe('operator');
    expect(requests[1]?.headers.get('open-card-role')).toBe('operator');
  });
});
