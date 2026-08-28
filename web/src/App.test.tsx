import type { ApplicationSummary } from './api/types';
import type { PublishEvent } from './domain/publishing';
import { vi } from 'vitest';
import { updateFromPublishEvent } from './domain/applicationEvents';
import { applicationIdFromLocation, resolveSelectedApplicationId, setApplicationQuery } from './components/applicationSelection';

const applications: ApplicationSummary[] = [
  { id: 'app-1', name: 'Portal', slug: 'portal', source: { kind: 'git' }, runtimeStatus: 'running', runtimeReady: true, serving: true, updatedAt: '2026-08-28T00:00:00Z' },
  { id: 'app-2', name: 'Docs', slug: 'docs', source: { kind: 'git' }, runtimeStatus: 'stopped', runtimeReady: false, serving: false, updatedAt: '2026-08-28T00:00:00Z' },
];

describe('application selection routing', () => {
  it('reads only the non-sensitive application query parameter', () => {
    expect(applicationIdFromLocation({ search: '?application=app-2' })).toBe('app-2');
    expect(applicationIdFromLocation({ search: '?token=secret' })).toBeUndefined();
    expect(applicationIdFromLocation({ search: '' })).toBeUndefined();
  });

  it('keeps a deep-link selection only when the refreshed list contains it', () => {
    expect(resolveSelectedApplicationId('app-2', applications)).toBe('app-2');
    expect(resolveSelectedApplicationId('deleted-app', applications)).toBeUndefined();
    expect(resolveSelectedApplicationId(undefined, applications)).toBeUndefined();
    expect(resolveSelectedApplicationId('app-1', [])).toBeUndefined();
  });

  it('writes only the selected application query and removes sensitive query values', () => {
    const replaceState = vi.fn();
    Object.defineProperty(globalThis, 'window', {
      configurable: true,
      value: {
        location: { href: 'https://console.example.test/console?token=secret&password=secret' },
        history: { state: null, replaceState },
      },
    });

    setApplicationQuery('app-2');

    expect(String(replaceState.mock.calls[0]?.[2])).toBe('https://console.example.test/console?application=app-2');
    Reflect.deleteProperty(globalThis, 'window');
  });

  it('does not infer runtime readiness from a succeeded publish event', () => {
    const event: PublishEvent = { id: 'evt-succeeded', operationId: 'op-1', applicationId: 'app-2', sequence: 4, occurredAt: '2026-08-28T00:00:01Z', kind: 'operation.succeeded', status: 'succeeded' };
    const result = updateFromPublishEvent([{ ...applications[1]!, publishing: { status: 'deploying', sequence: 3, evidenceIds: [] } }], event);

    expect(result[0]).toMatchObject({ runtimeStatus: 'stopped', runtimeReady: false, publishing: { status: 'succeeded' } });
  });
});
