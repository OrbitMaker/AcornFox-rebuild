import { renderToStaticMarkup } from 'react-dom/server';
import type { ApiClient, SourceUploadResponse } from '../api/types';
import { SourceUploadField } from './SourceUploadField';

const upload: SourceUploadResponse = {
  uploadId: 'upload-1',
  kind: 'archive',
  status: 'ready',
  digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  bytes: 12,
  fileCount: 1,
  expiresAt: '2026-08-28T01:00:00Z',
};

const client = {} as ApiClient;

describe('SourceUploadField', () => {
  it('renders archive/directory browser inputs and no path locator field', () => {
    const archiveMarkup = renderToStaticMarkup(<SourceUploadField client={client} value={upload} onUploaded={() => undefined} onCleared={() => undefined} />);
    const directoryMarkup = renderToStaticMarkup(<SourceUploadField client={client} initialMode="directory" onUploaded={() => undefined} onCleared={() => undefined} />);

    expect(archiveMarkup).toContain('type="file"');
    expect(archiveMarkup).toContain('选择 .zip / .tar.gz / .tgz');
    expect(archiveMarkup).toContain('upload-1');
    expect(archiveMarkup).toContain('sha256:aaaaaaaa');
    expect(directoryMarkup).toContain('webkitdirectory');
    expect(directoryMarkup).toContain('webkitRelativePath');
    expect(archiveMarkup + directoryMarkup).not.toContain('文件路径');
  });
});
