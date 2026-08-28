import {
  applyPublishingEvent,
  createPublishingSnapshot,
  isPublishingTerminal,
  isPublishEventKind,
  isPublishingStatus,
  publishingStatusLabel,
  type PublishEvent,
} from './publishing';

const event = (overrides: Partial<PublishEvent>): PublishEvent => ({
  id: 'evt-1',
  operationId: 'op-1',
  applicationId: 'app-1',
  sequence: 1,
  occurredAt: '2026-08-24T00:00:00.000Z',
  kind: 'operation.created',
  status: 'preparing',
  ...overrides,
});

describe('publishing state projection', () => {
  it('projects the five states in event order and keeps evidence', () => {
    let snapshot = createPublishingSnapshot();

    snapshot = applyPublishingEvent(snapshot, event({ sequence: 1 }));
    snapshot = applyPublishingEvent(snapshot, event({
      id: 'evt-2', sequence: 2, kind: 'build.started', status: 'building',
    }));
    snapshot = applyPublishingEvent(snapshot, event({
      id: 'evt-3', sequence: 3, kind: 'deployment.started', status: 'deploying',
    }));
    snapshot = applyPublishingEvent(snapshot, event({
      id: 'evt-4', sequence: 4, kind: 'operation.succeeded', status: 'succeeded',
      evidenceIds: ['evidence-4'],
    }));

    expect(snapshot.status).toBe('succeeded');
    expect(snapshot.sequence).toBe(4);
    expect(snapshot.evidenceIds).toEqual(['evidence-4']);
    expect(publishingStatusLabel(snapshot.status)).toBe('部署成功');
    expect(isPublishingTerminal(snapshot.status)).toBe(true);
  });

  it('ignores duplicate, stale, and post-terminal events', () => {
    const snapshot = applyPublishingEvent(
      applyPublishingEvent(createPublishingSnapshot(), event({ sequence: 2, id: 'evt-2', kind: 'build.started', status: 'building' })),
      event({ sequence: 3, id: 'evt-3', kind: 'operation.failed', status: 'failed' }),
    );

    expect(applyPublishingEvent(snapshot, event({ sequence: 3, id: 'duplicate', kind: 'operation.failed', status: 'failed' }))).toEqual(snapshot);
    expect(applyPublishingEvent(snapshot, event({ sequence: 4, id: 'late', kind: 'operation.succeeded', status: 'succeeded' }))).toEqual(snapshot);
    expect(applyPublishingEvent(snapshot, event({ sequence: 1, id: 'stale', kind: 'operation.created', status: 'preparing' }))).toEqual(snapshot);
  });

  it('rejects a transition that jumps back to preparation', () => {
    const snapshot = applyPublishingEvent(
      createPublishingSnapshot(),
      event({ sequence: 1, id: 'evt-2', kind: 'build.started', status: 'building' }),
    );

    expect(applyPublishingEvent(snapshot, event({ sequence: 2, id: 'evt-3', kind: 'operation.created', status: 'preparing' }))).toEqual(snapshot);
    expect(isPublishingTerminal(snapshot.status)).toBe(false);
  });

  it('rejects skipping the build and deployment phases', () => {
    const snapshot = createPublishingSnapshot();
    expect(applyPublishingEvent(snapshot, event({ sequence: 1, status: 'succeeded', kind: 'operation.succeeded' }))).toEqual(snapshot);
    expect(applyPublishingEvent(snapshot, event({ sequence: 1, status: 'deploying', kind: 'deployment.started' }))).toEqual(snapshot);
  });

  it('exposes runtime guards for the API event boundary', () => {
    expect(isPublishingStatus('deploying')).toBe(true);
    expect(isPublishingStatus('runtime_ready')).toBe(false);
    expect(isPublishEventKind('operation.succeeded')).toBe(true);
    expect(isPublishEventKind('container.started')).toBe(false);
  });
});
