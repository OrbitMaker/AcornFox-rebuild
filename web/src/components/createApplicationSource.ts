import { ApiRequestError } from '../api/errors';
import type { CreateApplicationSource, SourceUploadResponse } from '../api/types';

export function buildCreateApplicationSource(
  kind: CreateApplicationSource['kind'],
  upload: SourceUploadResponse | undefined,
  repositoryUrl: string,
  ref: string,
): CreateApplicationSource {
  if (kind === 'upload') {
    if (!upload || upload.status !== 'ready') throw new ApiRequestError(422, '请先完成文件上传，再创建应用。', 'validation', 'upload_not_ready');
    return { kind: 'upload', uploadId: upload.uploadId };
  }
  return { kind: 'git', repositoryUrl: repositoryUrl.trim(), ref: ref.trim() || 'main' };
}
