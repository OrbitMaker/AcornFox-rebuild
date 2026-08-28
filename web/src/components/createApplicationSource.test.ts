import { ApiRequestError } from '../api/errors';
import type { SourceUploadResponse } from '../api/types';
import { buildCreateApplicationSource } from './createApplicationSource';

const upload: SourceUploadResponse = {
  uploadId: 'upload-1',
  kind: 'directory',
  status: 'ready',
  digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  bytes: 12,
  fileCount: 2,
  expiresAt: '2026-08-28T01:00:00Z',
};

describe('create application source contract', () => {
  it('creates an upload source with only the upload ID', () => {
    expect(buildCreateApplicationSource('upload', upload, '', '')).toEqual({ kind: 'upload', uploadId: 'upload-1' });
  });

  it('does not create an upload source before a ready upload', () => {
    expect(() => buildCreateApplicationSource('upload', { ...upload, status: 'failed' }, '', '')).toThrowError(ApiRequestError);
  });

  it('keeps Git as an explicit HTTPS contract without a local locator', () => {
    expect(buildCreateApplicationSource('git', undefined, ' https://git.example.test/app.git ', ' ')).toEqual({ kind: 'git', repositoryUrl: 'https://git.example.test/app.git', ref: 'main' });
  });

});
