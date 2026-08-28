import { renderToStaticMarkup } from 'react-dom/server';
import { SseConnectionStatus, type SseConnectionState } from './SseConnectionStatus';

describe('SseConnectionStatus', () => {
  it.each(['connecting', 'connected', 'retrying', 'offline', 'auth_required', 'closed'] as const)('renders the %s state without percentages', (state: SseConnectionState) => {
    const markup = renderToStaticMarkup(<SseConnectionStatus state={state} lastEventId="evt-1" />);

    expect(markup).toContain('role="status"');
    expect(markup).toContain('evt-1');
    expect(markup).not.toMatch(/\d+%/);
  });
});
