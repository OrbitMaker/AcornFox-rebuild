import { ApiRequestError } from '../api/errors';
import { normalizeUploadPath } from '../api/client';
import type { SourceUploadManifest, SourceUploadManifestEntry } from '../api/types';

export const SOURCE_UPLOAD_LIMITS = {
  maxTotalBytes: 100 * 1024 * 1024,
  maxFileBytes: 32 * 1024 * 1024,
  maxFiles: 10_000,
  maxPathBytes: 512,
  maxManifestBytes: 2 * 1024 * 1024,
} as const;

export interface DirectorySelectionSummary {
  paths: string[];
  totalBytes: number;
}

function uploadLimitError(message: string): ApiRequestError {
  return new ApiRequestError(413, message, 'size', 'upload_limit_exceeded');
}

function invalidUploadError(message: string): ApiRequestError {
  return new ApiRequestError(422, message, 'validation', 'invalid_upload');
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
}

export function isSupportedArchive(filename: string): boolean {
  const normalized = filename.trim().toLowerCase();
  return normalized.endsWith('.zip') || normalized.endsWith('.tar.gz') || normalized.endsWith('.tgz');
}

export function validateArchiveFile(file: File): void {
  if (!isSupportedArchive(file.name)) throw new ApiRequestError(415, '仅支持 .zip、.tar.gz 或 .tgz 归档。', 'media', 'unsupported_media_type');
  if (file.size > SOURCE_UPLOAD_LIMITS.maxFileBytes) throw uploadLimitError(`归档超过单文件 ${formatBytes(SOURCE_UPLOAD_LIMITS.maxFileBytes)} 限制。`);
}

export function browserRelativePath(file: File): string {
  return (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
}

export function validateDirectoryFiles(files: readonly File[]): DirectorySelectionSummary {
  if (files.length === 0) throw invalidUploadError('请选择至少一个目录文件。');
  if (files.length > SOURCE_UPLOAD_LIMITS.maxFiles) throw uploadLimitError(`目录文件数超过 ${SOURCE_UPLOAD_LIMITS.maxFiles} 个限制。`);
  const paths = files.map(browserRelativePath);
  const seen = new Set<string>();
  let totalBytes = 0;
  for (const [index, rawPath] of paths.entries()) {
    let path: string;
    try {
      path = normalizeUploadPath(rawPath);
    } catch {
      throw invalidUploadError(`目录包含不安全的相对路径：${rawPath || '(空路径)'}`);
    }
    if (new TextEncoder().encode(path).byteLength > SOURCE_UPLOAD_LIMITS.maxPathBytes) throw uploadLimitError(`目录路径超过 ${SOURCE_UPLOAD_LIMITS.maxPathBytes} bytes：${path}`);
    if (seen.has(path)) throw invalidUploadError(`目录包含重复路径：${path}`);
    seen.add(path);
    const file = files[index];
    if (file.size > SOURCE_UPLOAD_LIMITS.maxFileBytes) throw uploadLimitError(`文件超过单文件 ${formatBytes(SOURCE_UPLOAD_LIMITS.maxFileBytes)} 限制：${path}`);
    totalBytes += file.size;
    if (totalBytes > SOURCE_UPLOAD_LIMITS.maxTotalBytes) throw uploadLimitError(`目录总大小超过 ${formatBytes(SOURCE_UPLOAD_LIMITS.maxTotalBytes)} 限制。`);
  }
  return { paths, totalBytes };
}

function sha256Hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (value) => value.toString(16).padStart(2, '0')).join('');
}

export async function sha256File(file: File, subtle: SubtleCrypto = globalThis.crypto?.subtle): Promise<string> {
  if (!subtle) throw new ApiRequestError(503, '当前浏览器不支持 SHA-256 文件摘要，无法安全上传。', 'unavailable', 'crypto_unavailable');
  return `sha256:${sha256Hex(await subtle.digest('SHA-256', await file.arrayBuffer()))}`;
}

export async function buildDirectoryManifest(files: readonly File[]): Promise<{ manifest: SourceUploadManifest; totalBytes: number }> {
  const { paths, totalBytes } = validateDirectoryFiles(files);
  const entries: SourceUploadManifestEntry[] = [];
  for (const [index, file] of files.entries()) {
    entries.push({ path: paths[index], bytes: file.size, digest: await sha256File(file) });
  }
  const manifest = { files: entries };
  if (new TextEncoder().encode(JSON.stringify(manifest)).byteLength > SOURCE_UPLOAD_LIMITS.maxManifestBytes) throw uploadLimitError(`目录 manifest 超过 ${formatBytes(SOURCE_UPLOAD_LIMITS.maxManifestBytes)} 限制。`);
  return { manifest, totalBytes };
}

export function sourceUploadErrorMessage(error: unknown, fallback = '上传未完成，请稍后重试。'): string {
  if (!(error instanceof ApiRequestError)) return error instanceof Error ? error.message : fallback;
  if (error.status === 413 || error.kind === 'size') return error.message || '上传内容超过限制。';
  if (error.status === 415 || error.kind === 'media') return error.message || '上传媒体类型不受支持。';
  if (error.status === 422 || error.kind === 'validation') return error.message || '上传内容未通过校验。';
  if (error.status === 503 || error.kind === 'unavailable') return error.message || '上传服务暂时不可用。';
  return error.message || fallback;
}
