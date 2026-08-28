import { createElement, type ReactNode } from 'react';
import { vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import type { ApplicationSummary } from '../api/types';
import { ApplicationList } from './ApplicationList';

vi.mock('@douyinfe/semi-icons', () => ({
  IconPlus: () => null,
  IconRefresh: () => null,
}));

interface MockButtonProps { children?: ReactNode; onClick?: () => void; disabled?: boolean; }
interface MockTableProps { dataSource: ApplicationSummary[]; columns: Array<{ render?: (value: unknown, row: ApplicationSummary) => ReactNode; dataIndex?: string }>; }

vi.mock('@douyinfe/semi-ui', () => ({
  Button: ({ children, onClick, disabled }: MockButtonProps) => createElement('button', { type: 'button', onClick, disabled }, children),
  Empty: ({ description }: { description: string }) => createElement('div', null, description),
  Table: ({ dataSource, columns }: MockTableProps) => createElement(
    'div',
    null,
    dataSource.map((row) => createElement(
      'div',
      { key: row.id },
      columns.map((column, index) => createElement(
        'div',
        { key: `${row.id}-${index}` },
        column.render ? column.render(column.dataIndex ? row[column.dataIndex as keyof ApplicationSummary] : undefined, row) : null,
      )),
    )),
  ),
  Tag: ({ children }: MockButtonProps) => createElement('span', null, children),
}));

const application = (id: string, name: string): ApplicationSummary => ({
  id,
  name,
  slug: id,
  source: { kind: 'git', locator: 'https://git.example.test/repo.git', ref: 'main' },
  runtimeStatus: 'running',
  runtimeReady: true,
  serving: true,
  updatedAt: '2026-08-28T00:00:00Z',
});

const callbacks = {
  onCreate: () => undefined,
  onRefresh: () => undefined,
  onSelect: () => undefined,
};

describe('ApplicationList', () => {
  it('renders an explicitly selected application', () => {
    const markup = renderToStaticMarkup(<ApplicationList applications={[application('app-1', 'Portal'), application('app-2', 'Docs')]} loading={false} selectedApplicationId="app-2" {...callbacks} />);

    expect(markup).toContain('Portal');
    expect(markup).toContain('Docs');
    expect(markup).toContain('aria-pressed="true"');
    expect(markup).toContain('aria-pressed="false"');
  });

  it('renders the empty-list path without inventing an application selection', () => {
    const markup = renderToStaticMarkup(<ApplicationList applications={[]} loading={false} {...callbacks} />);

    expect(markup).toContain('还没有应用');
    expect(markup).toContain('接入第一个应用');
    expect(markup).not.toContain('aria-pressed="true"');
  });

  it('renders upload IDs and unknown sources without falling back to Git', () => {
    const archive = { ...application('app-archive', 'Archive'), source: { kind: 'archive' as const, uploadId: 'upload-1' } };
    const folder = { ...application('app-folder', 'Folder'), source: { kind: 'folder' as const } };
    const unknown = { ...application('app-unknown', 'Unknown'), source: { kind: 'unknown' as const } };
    const markup = renderToStaticMarkup(<ApplicationList applications={[archive, folder, unknown]} loading={false} {...callbacks} />);

    expect(markup).toContain('upload:upload-1');
    expect(markup).toContain('上传 ID 未记录');
    expect(markup).toContain('来源未记录');
    expect(markup).not.toContain('待接入来源');
  });
});
