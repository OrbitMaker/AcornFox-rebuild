import { createElement, type ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { vi } from 'vitest';
import { PublishingStatusTag, PublishingStatusTrack } from './PublishingStatus';

vi.mock('@douyinfe/semi-ui', () => ({
  Tag: ({ children }: { children?: ReactNode }) => createElement('span', null, children),
}));

describe('PublishingStatus', () => {
  it('does not report an unpublished application as preparing', () => {
    expect(renderToStaticMarkup(<PublishingStatusTag />)).toContain('未发布');
    expect(renderToStaticMarkup(<PublishingStatusTrack />)).toContain('尚未发起发布');
    expect(renderToStaticMarkup(<PublishingStatusTrack />)).not.toContain('准备中');
  });

  it('renders a real publishing fact when one exists', () => {
    const snapshot = { status: 'building' as const, sequence: 2, evidenceIds: [] };
    expect(renderToStaticMarkup(<PublishingStatusTag snapshot={snapshot} />)).toContain('构建中');
    expect(renderToStaticMarkup(<PublishingStatusTrack snapshot={snapshot} />)).toContain('发布状态：构建中');
  });
});
