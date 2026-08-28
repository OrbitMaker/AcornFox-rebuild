import { ApiRequestError, RestApiClient, StubApiClient } from './client';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from '../features/auth/auth';
import { vi } from 'vitest';

class FakeEventSource {
  private listeners = new Map<string, Set<EventListener>>();
  closed = false;
  options?: EventSourceInit & { lastEventId?: string };
  onerror?: ((event: Event) => void) | null;
  onopen?: ((event: Event) => void) | null;

  addEventListener(type: string, listener: EventListener): void {
    const listeners = this.listeners.get(type) ?? new Set<EventListener>();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type: string, listener: EventListener): void {
    this.listeners.get(type)?.delete(listener);
  }

  close(): void {
    this.closed = true;
  }

  emit(data: string): void {
    this.listeners.get('message')?.forEach((listener) => listener(new MessageEvent('message', { data })));
  }

  emitOpen(): void {
    this.onopen?.(new Event('open'));
  }

  emitError(status?: number): void {
    const event = new Event('error') as Event & { status?: number };
    event.status = status;
    this.onerror?.(event);
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function domainFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 'domain-1',
    hostname: 'portal.apps.example.test',
    kind: 'platform',
    status: 'ready',
    cname_target: 'ingress.example.test',
    verification: { method: 'cname', status: 'ready', name: null, value: null, observed_at: '2026-08-28T00:00:00Z' },
    certificate: { status: 'ready', subject: 'portal.apps.example.test', not_after: '2027-08-28T00:00:00Z' },
    failure: null,
    serving: true,
    ...overrides,
  };
}

function platformDomainFixture() {
  return {
    status: 'ready',
    base_domain: 'example.test',
    console_domain: 'console.example.test',
    wildcard_pattern: '*.apps.example.test',
    verification: { method: 'cname', status: 'ready', name: null, value: null, observed_at: '2026-08-28T00:00:00Z' },
    certificate: { status: 'ready', subject: '*.apps.example.test', not_after: '2027-08-28T00:00:00Z' },
    failure: null,
    next_action: 'ready',
  };
}

function accessFixture() {
  return {
    runtimeReady: true,
    ipFallback: '198.51.100.20',
    platformAddress: domainFixture(),
    customDomains: [domainFixture({ id: 'domain-2', hostname: 'portal.example.com', kind: 'custom', cname_target: 'ingress.example.test' })],
    route: { desired: true, serving: true, route_id: 'route-1' },
    certificate: { status: 'ready', subject: 'portal.apps.example.test', not_after: '2027-08-28T00:00:00Z' },
    serving: true,
  };
}

function uploadFixture(kind: 'archive' | 'directory' = 'archive') {
  return {
    id: 'upload-1',
    kind,
    status: 'ready',
    digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    bytes: 12,
    file_count: kind === 'archive' ? 1 : 2,
    expires_at: '2026-08-28T01:00:00Z',
  };
}

function publishEvent(id: string, sequence: number, operationId = 'op-live') {
  return {
    id,
    operation_id: operationId,
    application_id: 'app-live',
    sequence,
    occurred_at: `2026-08-28T00:00:0${sequence}Z`,
    kind: 'operation.created',
    status: 'preparing',
  };
}

function streamResponse(events: unknown[]): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      events.forEach((event) => {
        const payload = event as { id: string };
        controller.enqueue(encoder.encode(`id: ${payload.id}\ndata: ${JSON.stringify(event)}\n\n`));
      });
      controller.close();
    },
  });
  return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

function fakeFile(name: string, content = 'file'): File {
  const file = new Blob([content], { type: 'text/plain' }) as File;
  Object.defineProperty(file, 'name', { configurable: true, value: name });
  return file;
}

describe('StubApiClient', () => {
  it('uses the same typed create and event contract as the live client', async () => {
    const client = new StubApiClient();
    await client.login({ username: 'admin', password: 'local-demo-password' });
    const created = await client.createApplication({
      name: 'Release Demo',
      source: { kind: 'git', repositoryUrl: 'https://git.example.invalid/demo.git', ref: 'main' },
    });
    const events: string[] = [];
    const unsubscribe = client.subscribeToPublishEvents(created.operationId, (event) => events.push(event.status));

    await new Promise((resolve) => setTimeout(resolve, 1_800));
    unsubscribe();

    expect(created.application.operationId).toBe(created.operationId);
    expect(events).toEqual(['preparing', 'building', 'deploying', 'succeeded']);
    expect((await client.listApplications()).items[0]?.name).toBe('Release Demo');
  }, 4_000);

  it('does not claim live domain or upload capability in Stub mode', async () => {
    const client = new StubApiClient();
    await client.login({ username: 'admin', password: 'local-demo-password' });

    await expect(client.getPlatformDomainSettings()).rejects.toMatchObject({ kind: 'unavailable', code: 'stub_unavailable' });
    await expect(client.listApplicationDomains('app-notes')).rejects.toMatchObject({ kind: 'unavailable', code: 'stub_unavailable' });
    await expect(client.getApplicationAccess('app-notes')).rejects.toMatchObject({ kind: 'unavailable', code: 'stub_unavailable' });
    await expect(client.createSourceUpload({ mode: 'archive', archive: new Blob(['demo']) })).rejects.toMatchObject({ kind: 'unavailable', code: 'stub_unavailable' });
    await expect(client.getSourceUpload('upload-1')).rejects.toMatchObject({ kind: 'unavailable', code: 'stub_unavailable' });

    await expect(client.getApplication('app-notes')).resolves.toMatchObject({ id: 'app-notes', sourceUploadId: null, access: { platformAddress: null } });
  });
});

describe('RestApiClient', () => {
  it('normalizes the current OpenAPI Application response and validates SSE events', async () => {
    const eventSource = new FakeEventSource();
    const requested: Array<{ url: string; method?: string; credentials?: RequestCredentials }> = [];
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async (input, init) => {
        requested.push({ url: String(input), method: init?.method, credentials: init?.credentials });
        if (init?.method === 'POST') {
          return new Response(JSON.stringify({ id: 'app-live', name: 'Live App', created_at: '2026-08-24T00:00:00.000Z', updated_at: '2026-08-24T00:00:00.000Z' }), { status: 201, headers: { 'content-type': 'application/json' } });
        }
        return new Response(JSON.stringify([{ id: 'app-live', name: 'Live App', created_at: '2026-08-24T00:00:00.000Z', updated_at: '2026-08-24T00:00:00.000Z' }]), { status: 200, headers: { 'content-type': 'application/json' } });
      },
      eventSourceFactory: (_url, init) => { eventSource.options = init; return eventSource as unknown as EventSource; },
    });

    const list = await client.listApplications();
    const created = await client.createApplication({ name: 'Live App', source: { kind: 'git', repositoryUrl: 'https://git.example.test/repo.git', ref: 'main' } });
    const events: string[] = [];
    const unsubscribe = client.subscribeToPublishEvents(created.operationId, (event) => events.push(event.status));
    eventSource.emit(JSON.stringify({ id: 'evt-1', operation_id: created.operationId, application_id: 'app-live', sequence: 1, occurred_at: '2026-08-24T00:00:01.000Z', kind: 'operation.created', status: 'preparing' }));
    eventSource.emit(JSON.stringify({ id: 'bad', operation_id: created.operationId, application_id: 'app-live', sequence: 2, occurred_at: '2026-08-24T00:00:02.000Z', kind: 'unknown', status: 'preparing' }));
    unsubscribe();

    expect(list.items[0]?.source.kind).toBe('unknown');
    expect(created.operationId).toBe('application:app-live');
    expect(events).toEqual(['preparing']);
    expect(eventSource.closed).toBe(true);
    expect(eventSource.options?.withCredentials).toBe(true);
    expect(requested.map((request) => request.url)).toEqual(['/api/v1/applications', '/api/v1/applications']);
    expect(requested.every((request) => request.credentials === 'same-origin')).toBe(true);
  });

  it('preserves the G3E upload source ID and does not infer a missing source as Git', async () => {
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async () => new Response(JSON.stringify({ items: [
        { id: 'app-upload', name: 'Uploaded', source: { kind: 'archive', source_upload_id: 'upload-1', locator: 'upload://private' }, created_at: '2026-08-28T00:00:00Z', updated_at: '2026-08-28T00:00:00Z' },
        { id: 'app-unknown', name: 'Unknown', created_at: '2026-08-28T00:00:00Z', updated_at: '2026-08-28T00:00:00Z' },
      ] }), { status: 200 }),
    });

    await expect(client.listApplications()).resolves.toMatchObject({ items: [
      { source: { kind: 'archive', uploadId: 'upload-1' } },
      { source: { kind: 'unknown' } },
    ] });
  });

  it('sends the upload source union without a folder or archive locator', async () => {
    let request: RequestInit | undefined;
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async (_input, init) => {
        request = init;
        return jsonResponse({
          application: { id: 'app-upload', name: 'Uploaded App', created_at: '2026-08-28T00:00:00Z', updated_at: '2026-08-28T00:00:00Z' },
          environment_id: 'env-upload',
          operation_id: 'op-upload',
          source_revision_id: 'source-upload',
        }, 201);
      },
    });

    await client.createApplication({ name: 'Uploaded App', source: { kind: 'upload', uploadId: 'upload-1' } });

    expect(JSON.parse(String(request?.body))).toEqual({ name: 'Uploaded App', source: { kind: 'upload', upload_id: 'upload-1' } });
    expect(JSON.stringify(request?.body)).not.toContain('locator');
    expect(JSON.stringify(request?.body)).not.toContain('folder');
    expect(JSON.stringify(request?.body)).not.toContain('archive');
  });

  it('sends the publish facade contract with the bounded request timeout', async () => {
    let request: RequestInit | undefined;
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async (_input, init) => {
        request = init;
        return jsonResponse({ status: 'deploying', operation_id: 'op-1', release_id: 'rel-1', deployment_id: 'dep-1', task_id: 'task-1', source_revision_id: 'src-1' }, 202);
      },
    });

    await expect(client.publishApplication('app-1', { buildKind: 'dockerfile', contextPath: '.', dockerfilePath: 'Dockerfile', serviceName: 'web', containerPort: 8080 })).resolves.toMatchObject({ operationId: 'op-1', status: 'deploying' });
    expect(JSON.parse(String(request?.body))).toEqual({ build_kind: 'dockerfile', context_path: '.', dockerfile_path: 'Dockerfile', service_name: 'web', container_port: 8080 });
    expect(request?.credentials).toBe('same-origin');
    expect(request?.signal).toBeInstanceOf(AbortSignal);
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
    await expect(client.requestApplicationOperation('app-live', { action: 'restart', expectedVersion: 'ops-v1' })).resolves.toEqual({
      status: 'unavailable',
      message: '运行与运维操作 API 尚未由控制面组合，未发送操作。',
    });
  });

  it('passes fact version and idempotency headers without claiming action success', async () => {
    let request: RequestInit | undefined;
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async (_input, init) => {
        request = init;
        return new Response(JSON.stringify({ operation_id: 'op-queued' }), { status: 202 });
      },
    });

    const result = await client.requestApplicationOperation('app-live', { action: 'restart', targetServiceId: 'api', expectedVersion: 'ops-v9' });
    const headers = new Headers(request?.headers);

    expect(result).toEqual({ status: 'accepted', operationId: 'op-queued', message: '控制面已接受操作请求，正在等待新的事实版本。' });
    expect([...headers.keys()].sort()).toEqual(['content-type', 'idempotency-key']);
    expect(headers.get('idempotency-key')).toMatch(/^m4-operation:app-live:/);
    expect(request?.body).toBe(JSON.stringify({ action: 'restart', target_service_id: 'api', expected_version: 'ops-v9', reason: 'operator requested restart after reviewing facts ops-v9' }));
  });

  it('normalizes M5 usage facts without client-side identity claims', async () => {
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
    expect([...new Headers(request?.headers).keys()]).toEqual([]);
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
    expect([...requests[0].headers.keys()]).toEqual([]);
    expect([...requests[1].headers.keys()]).toEqual([]);
  });

  it('implements the 9038b2a application, domain, access and upload routes', async () => {
    Object.defineProperty(globalThis, 'document', { configurable: true, value: { cookie: `${CSRF_COOKIE_NAME}=csrf-value` } });
    const requests: Array<{ url: string; method: string; init: RequestInit }> = [];
    const responses = [
      jsonResponse({ id: 'app/live', name: 'Live App', created_at: '2026-08-28T00:00:00Z', updated_at: '2026-08-28T00:00:00Z', source_upload_id: 'upload-1', access: accessFixture() }),
      jsonResponse(platformDomainFixture()),
      jsonResponse(platformDomainFixture(), 202),
      jsonResponse({ items: [domainFixture()] }),
      jsonResponse({ domain: domainFixture({ id: 'domain-2', kind: 'custom', hostname: 'portal.example.com' }) }, 202),
      jsonResponse({ domain: domainFixture({ id: 'domain-2', kind: 'custom', status: 'verifying', hostname: 'portal.example.com' }) }, 202),
      new Response(null, { status: 204 }),
      jsonResponse(accessFixture()),
      jsonResponse(uploadFixture(), 201),
      jsonResponse(uploadFixture()),
    ];
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async (input, init) => {
        requests.push({ url: String(input), method: init?.method ?? 'GET', init: init ?? {} });
        const response = responses.shift();
        if (!response) throw new Error('unexpected request');
        return response;
      },
    });

    const detail = await client.getApplication('app/live');
    const platform = await client.getPlatformDomainSettings();
    const updatedPlatform = await client.putPlatformDomainSettings({ baseDomain: 'example.test' });
    const domains = await client.listApplicationDomains('app/live');
    const bound = await client.bindApplicationCustomDomain('app/live', { hostname: 'portal.example.com' });
    const verified = await client.verifyApplicationDomain('app/live', 'domain-2');
    await client.unbindApplicationDomain('app/live', 'domain-2');
    const access = await client.getApplicationAccess('app/live');
    const upload = await client.createSourceUpload({ mode: 'archive', archive: new Blob(['archive'], { type: 'application/gzip' }) });
    const uploadStatus = await client.getSourceUpload(upload.uploadId);

    expect(detail.sourceUploadId).toBe('upload-1');
    expect(platform.wildcardPattern).toBe('*.apps.example.test');
    expect(updatedPlatform.nextAction).toBe('ready');
    expect(domains.items[0]?.hostname).toBe('portal.apps.example.test');
    expect(bound.domain.kind).toBe('custom');
    expect(verified.domain.status).toBe('verifying');
    expect(access.ipFallback).toBe('198.51.100.20');
    expect(upload.kind).toBe('archive');
    expect(uploadStatus.uploadId).toBe('upload-1');
    expect(requests.map((request) => `${request.method} ${request.url}`)).toEqual([
      'GET /api/v1/applications/app%2Flive',
      'GET /api/v1/settings/platform-domain',
      'PUT /api/v1/settings/platform-domain',
      'GET /api/v1/applications/app%2Flive/domains',
      'POST /api/v1/applications/app%2Flive/domains',
      'POST /api/v1/applications/app%2Flive/domains/domain-2/verify',
      'DELETE /api/v1/applications/app%2Flive/domains/domain-2',
      'GET /api/v1/applications/app%2Flive/access',
      'POST /api/v1/source-uploads',
      'GET /api/v1/source-uploads/upload-1',
    ]);
    expect(requests.every(({ init }) => init.credentials === 'same-origin' && init.signal instanceof AbortSignal)).toBe(true);
    const writes = requests.filter(({ method }) => method !== 'GET');
    expect(writes.every(({ init }) => {
      const headers = new Headers(init.headers);
      return headers.get(CSRF_HEADER_NAME) === 'csrf-value' && Boolean(headers.get('Idempotency-Key'));
    })).toBe(true);
    expect(JSON.parse(String(requests[2]?.init.body))).toEqual({ base_domain: 'example.test' });
    const archiveBody = requests[8]?.init.body;
    expect(archiveBody).toBeInstanceOf(FormData);
    expect((archiveBody as FormData).get('mode')).toBe('archive');
    expect((archiveBody as FormData).get('archive')).toBeInstanceOf(Blob);
    Reflect.deleteProperty(globalThis, 'document');
  });

  it('accepts only safe mutually exclusive archive or directory multipart inputs', async () => {
    const requests: RequestInit[] = [];
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async (_input, init) => {
        requests.push(init ?? {});
        return jsonResponse(uploadFixture('directory'), 201);
      },
    });
    const first = fakeFile('src/index.html', '<h1>ok</h1>');
    Object.defineProperty(first, 'webkitRelativePath', { configurable: true, value: 'src/index.html' });
    const second = fakeFile('src/app.js', 'console.log(1)');
    Object.defineProperty(second, 'webkitRelativePath', { configurable: true, value: 'src/app.js' });
    const manifest = { files: [{ path: 'src/index.html', bytes: first.size }, { path: 'src/app.js', bytes: second.size }] };
    await expect(client.createSourceUpload({ mode: 'directory', files: [first, second], manifest })).resolves.toMatchObject({ kind: 'directory' });

    const form = requests[0]?.body as FormData;
    const uploadedFiles = form.getAll('files');
    expect(uploadedFiles.map((file) => file instanceof Blob && 'name' in file ? file.name : '')).toEqual(['src/index.html', 'src/app.js']);
    expect(JSON.parse(await (form.get('manifest') as Blob).text())).toEqual(manifest);
    expect(JSON.stringify([...form.entries()])).not.toContain('/Users/');

    const archiveForm = new FormData();
    archiveForm.append('mode', 'archive');
    archiveForm.append('archive', new Blob(['archive']), 'archive.zip');
    await expect(client.createSourceUpload(archiveForm)).resolves.toHaveProperty('uploadId', 'upload-1');
    const normalizedArchive = requests[1]?.body as FormData;
    expect(normalizedArchive.get('mode')).toBe('archive');
    expect(normalizedArchive.get('files')).toBeNull();

    for (const unsafePath of ['', '/absolute/file', 'C:/absolute/file', 'src/../file', 'src//file', 'src/', 'src\\file', '.']) {
      const file = fakeFile(unsafePath || 'file');
      Object.defineProperty(file, 'webkitRelativePath', { configurable: true, value: unsafePath });
      await expect(client.createSourceUpload({ mode: 'directory', files: [file], manifest: { files: [{ path: unsafePath, bytes: file.size }] } })).rejects.toMatchObject({ kind: 'validation', code: 'invalid_upload' });
    }

    const mixed = new FormData();
    mixed.append('mode', 'archive');
    mixed.append('archive', new Blob(['archive']), 'archive.zip');
    mixed.append('files', first, 'src/index.html');
    await expect(client.createSourceUpload(mixed)).rejects.toMatchObject({ kind: 'validation', code: 'invalid_upload' });
    await expect(client.createSourceUpload({ mode: 'directory', files: [first], manifest: { files: [{ path: 'src/index.html', bytes: 999 }] } })).rejects.toMatchObject({ kind: 'validation', code: 'invalid_upload' });
  });

  it.each([
    [401, 'auth'],
    [409, 'conflict'],
    [413, 'size'],
    [415, 'media'],
    [422, 'validation'],
    [429, 'rate'],
    [503, 'unavailable'],
    [500, 'unavailable'],
  ] as const)('maps HTTP %s to the stable %s error kind', async (status, kind) => {
    let unauthorized = 0;
    const client = new RestApiClient({
      fetchImpl: async () => jsonResponse({ code: 'safe_error', message: 'safe message', secret: 'ignored' }, status),
      onUnauthorized: () => { unauthorized += 1; },
    });
    await expect(client.getApplicationAccess('app-live')).rejects.toMatchObject({ status, kind, code: 'safe_error', message: 'safe message' });
    expect(unauthorized).toBe(status === 401 ? 1 : 0);
  });

  it('distinguishes timeout from network failure and forwards caller AbortSignal', async () => {
    const timedOut = new RestApiClient({
      timeoutMs: 5,
      fetchImpl: async (_input, init) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted by timeout')), { once: true });
      }),
    });
    await expect(timedOut.getApplicationAccess('app-live')).rejects.toMatchObject({ kind: 'timeout', code: 'request_timeout' });

    const network = new RestApiClient({ fetchImpl: async () => { throw new Error('socket failure'); } });
    await expect(network.getApplicationAccess('app-live')).rejects.toMatchObject({ kind: 'network', code: 'network_error' });

    const controller = new AbortController();
    let receivedSignal: AbortSignal | undefined;
    const callerAbort = new RestApiClient({
      fetchImpl: async (_input, init) => {
        receivedSignal = init?.signal ?? undefined;
        return new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('caller abort')), { once: true }));
      },
    });
    const pending = callerAbort.getApplicationAccess('app-live', controller.signal);
    controller.abort();
    await expect(pending).rejects.toThrow('caller abort');
    expect(receivedSignal).toBeInstanceOf(AbortSignal);
  });

  it('reconnects fake EventSource with bounded backoff, Last-Event-ID and deduplication', async () => {
    vi.useFakeTimers();
    try {
      const sources: FakeEventSource[] = [];
      const states: string[] = [];
      let unauthorized = 0;
      const client = new RestApiClient({
        baseUrl: '/api/v1',
        eventSourceFactory: (_url, init) => {
          const source = new FakeEventSource();
          source.options = init;
          sources.push(source);
          return source as unknown as EventSource;
        },
        onUnauthorized: () => { unauthorized += 1; },
      });
      const received: string[] = [];
      const unsubscribe = client.subscribeToPublishEvents('op-live', (event) => received.push(event.id), (state) => states.push(state));
      sources[0]?.emitOpen();
      sources[0]?.emit(JSON.stringify(publishEvent('evt-1', 1)));
      sources[0]?.emit(JSON.stringify(publishEvent('evt-1', 1)));
      sources[0]?.emitError();
      await vi.advanceTimersByTimeAsync(999);
      expect(sources).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(sources).toHaveLength(2);
      expect(sources[1]?.options?.lastEventId).toBe('evt-1');
      sources[1]?.emitOpen();
      sources[1]?.emitError();
      await vi.advanceTimersByTimeAsync(2_000);
      expect(sources).toHaveLength(3);
      sources[2]?.emitError();
      await vi.advanceTimersByTimeAsync(5_000);
      expect(sources).toHaveLength(4);
      unsubscribe();
      const countAfterClose = sources.length;
      await vi.advanceTimersByTimeAsync(30_000);
      expect(sources).toHaveLength(countAfterClose);
      expect(received).toEqual(['evt-1']);
      expect(unauthorized).toBe(0);
      expect(states[0]).toBe('connecting');
      expect(states).toContain('connected');
      expect(states).toContain('offline');
      expect(states).toContain('retrying');
      expect(states.at(-1)).toBe('closed');

      const authSources: FakeEventSource[] = [];
      const authStates: string[] = [];
      const authClient = new RestApiClient({
        eventSourceFactory: (_url, init) => {
          const source = new FakeEventSource();
          source.options = init;
          authSources.push(source);
          return source as unknown as EventSource;
        },
        onUnauthorized: () => { unauthorized += 1; },
      });
      authClient.subscribeToPublishEvents('op-auth', () => undefined, (state) => authStates.push(state));
      authSources[0]?.emitError(401);
      await vi.advanceTimersByTimeAsync(30_000);
      expect(authSources).toHaveLength(1);
      expect(unauthorized).toBe(1);
      expect(authStates).toEqual(['connecting', 'auth_required']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('uses fetch SSE with Last-Event-ID when no EventSource test double is supplied', async () => {
    vi.useFakeTimers();
    try {
      const requests: Array<{ url: string; headers: Headers; credentials?: RequestCredentials }> = [];
      let call = 0;
      const client = new RestApiClient({
        baseUrl: '/api/v1',
        fetchImpl: async (input, init) => {
          requests.push({ url: String(input), headers: new Headers(init?.headers), credentials: init?.credentials });
          call += 1;
          return streamResponse(call === 1 ? [publishEvent('evt-1', 1)] : [publishEvent('evt-1', 1), publishEvent('evt-2', 2)]);
        },
      });
      const received: string[] = [];
      const states: string[] = [];
      const unsubscribe = client.subscribeToPublishEvents('op-live', (event) => received.push(event.id), (state) => states.push(state));
      for (let index = 0; index < 8; index += 1) await Promise.resolve();
      await vi.advanceTimersByTimeAsync(1_000);
      for (let index = 0; index < 8; index += 1) await Promise.resolve();
      unsubscribe();
      expect(requests.map((request) => request.url)).toEqual(['/api/v1/operations/op-live/events', '/api/v1/operations/op-live/events']);
      expect(requests.every((request) => request.credentials === 'same-origin')).toBe(true);
      expect(requests[1]?.headers.get('Last-Event-ID')).toBe('evt-1');
      expect(received).toEqual(['evt-1', 'evt-2']);
      expect(states).toContain('connecting');
      expect(states).toContain('connected');
      expect(states).toContain('retrying');
      expect(states.at(-1)).toBe('closed');
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('Authentication client', () => {
  afterEach(() => {
    Reflect.deleteProperty(globalThis, 'document');
  });

  it('uses same-origin credentials and double-submit CSRF on every auth write', async () => {
    Object.defineProperty(globalThis, 'document', { configurable: true, value: { cookie: `${CSRF_COOKIE_NAME}=csrf-value` } });
    const requests: Array<{ url: string; method: string; credentials?: RequestCredentials; headers: Headers; body?: BodyInit | null }> = [];
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async (input, init) => {
        requests.push({ url: String(input), method: init?.method ?? 'GET', credentials: init?.credentials, headers: new Headers(init?.headers), body: init?.body });
        if (String(input).endsWith('/auth/session')) return new Response(JSON.stringify({ authenticated: false }), { status: 200 });
        if (String(input).endsWith('/auth/login')) return new Response(JSON.stringify({ authenticated: true, username: 'admin' }), { status: 200 });
        return new Response(null, { status: 204 });
      },
    });

    await expect(client.getSession()).resolves.toMatchObject({ authenticated: false, mode: 'live' });
    await expect(client.login({ username: 'admin', password: 'not-a-real-password' })).resolves.toMatchObject({ authenticated: true, username: 'admin' });
    expect(JSON.parse(String(requests.find((request) => request.url.endsWith('/auth/login'))?.body))).toEqual({ password: 'not-a-real-password' });
    await expect(client.logout()).resolves.toBeUndefined();
    await expect(client.changePassword({ currentPassword: 'old-password', newPassword: 'new-password' })).resolves.toMatchObject({ authenticated: false, mode: 'live' });

    expect(requests.every((request) => request.credentials === 'same-origin')).toBe(true);
    expect(requests.filter((request) => request.method === 'POST')).toHaveLength(3);
    expect(requests.filter((request) => request.method === 'POST').every((request) => request.headers.get(CSRF_HEADER_NAME) === 'csrf-value')).toBe(true);
    expect(requests.filter((request) => request.method === 'POST').every((request) => request.headers.has('Idempotency-Key'))).toBe(true);
    expect(requests.find((request) => request.url.endsWith('/auth/password'))?.body).toBe(JSON.stringify({ current_password: 'old-password', new_password: 'new-password' }));
  });

  it('handles an unauthenticated session without leaking an error', async () => {
    const client = new RestApiClient({
      fetchImpl: async (_input, init) => {
        expect(init?.credentials).toBe('same-origin');
        return new Response(JSON.stringify({ code: 'unauthorized' }), { status: 401 });
      },
    });
    await expect(client.getSession()).resolves.toEqual({ authenticated: false, mode: 'live' });
  });

  it('notifies the app on 401 and maps 429/503 to safe errors', async () => {
    let invalidations = 0;
    const unauthorized = new RestApiClient({ fetchImpl: async () => new Response('{}', { status: 401 }), onUnauthorized: () => { invalidations += 1; } });
    await expect(unauthorized.listApplications()).rejects.toMatchObject({ status: 401, message: '管理员会话已失效，请重新登录。' });
    expect(invalidations).toBe(1);

    const tooMany = new RestApiClient({ fetchImpl: async () => new Response('{}', { status: 429 }) });
    await expect(tooMany.login({ username: 'admin', password: 'not-a-real-password' })).rejects.toMatchObject({ status: 429, message: '请求过于频繁，请稍后再试。' });
    const unavailable = new RestApiClient({ fetchImpl: async () => new Response('{}', { status: 503 }) });
    await expect(unavailable.login({ username: 'admin', password: 'not-a-real-password' })).rejects.toMatchObject({ status: 503, message: '控制面暂时不可用，请稍后重试。' });
  });

  it('keeps stub authentication in memory and requires login before protected data', async () => {
    const client = new StubApiClient();
    expect(client.authMode).toBe('stub');
    await expect(client.listApplications()).rejects.toBeInstanceOf(ApiRequestError);
    await expect(client.login({ username: 'admin', password: 'local-demo-password' })).resolves.toMatchObject({ authenticated: true, mode: 'stub' });
    await expect(client.listApplications()).resolves.toHaveProperty('items');
    await expect(client.changePassword({ currentPassword: 'local-demo-password', newPassword: 'another-local-password' })).resolves.toMatchObject({ authenticated: false, mode: 'stub' });
    await expect(client.listApplications()).rejects.toBeInstanceOf(ApiRequestError);
  });

  it('normalizes the authenticated system status contract without inventing provider health', async () => {
    const client = new RestApiClient({
      baseUrl: '/api/v1',
      fetchImpl: async () => new Response(JSON.stringify({
        version: '1.1',
        node: { single_node: true, instance_id: null, node_id: 'node-1', readiness: 'ready' },
        platform_domain: { status: 'unconfigured', base_domain: null },
        webhooks: { status: 'unconfigured', enabled_count: 0 },
        backup: { status: 'not_installed' },
        alerts: { status: 'not_installed' },
      }), { status: 200 }),
    });
    await expect(client.getSystemStatus()).resolves.toEqual({
      status: 'available',
      facts: {
        version: '1.1',
        node: { singleNode: true, instanceId: null, nodeId: 'node-1', readiness: 'ready' },
        platformDomain: { status: 'unconfigured', baseDomain: null },
        webhooks: { status: 'unconfigured', enabledCount: 0 },
        backup: { status: 'not_installed' },
        alerts: { status: 'not_installed' },
      },
    });
  });

  it('binds the browser fetch implementation before calling it as a client member', async () => {
    const originalFetch = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = function (input, init) {
      calls.push(String(input));
      return originalFetch(input, init);
    };
    try {
      const client = new RestApiClient({ baseUrl: 'https://example.test/api/v1' });
      await expect(client.getSession()).rejects.toMatchObject({ kind: 'network' });
      expect(calls).toEqual(['https://example.test/api/v1/auth/session']);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
