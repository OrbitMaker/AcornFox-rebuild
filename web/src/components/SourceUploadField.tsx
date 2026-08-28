import { useEffect, useRef, useState } from 'react';
import type { ChangeEvent } from 'react';
import type { ApiClient, SourceUploadManifest, SourceUploadResponse } from '../api/types';
import { ApiRequestError } from '../api/errors';
import { buildDirectoryManifest, formatBytes, sourceUploadErrorMessage, validateArchiveFile, validateDirectoryFiles } from './sourceUpload';
import './SourceUploadField.css';

type UploadMode = 'archive' | 'directory';

export interface SourceUploadFieldProps {
  client: ApiClient;
  value?: SourceUploadResponse;
  initialMode?: UploadMode;
  disabled?: boolean;
  onUploaded: (upload: SourceUploadResponse) => void;
  onCleared: () => void;
  onError?: (error: unknown) => void;
}

export function SourceUploadField({ client, value, initialMode = 'archive', disabled = false, onUploaded, onCleared, onError }: SourceUploadFieldProps) {
  const [mode, setMode] = useState<UploadMode>(initialMode);
  const [files, setFiles] = useState<File[]>([]);
  const [manifest, setManifest] = useState<SourceUploadManifest>();
  const [totalBytes, setTotalBytes] = useState(0);
  const [hashing, setHashing] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<unknown>();
  const [selectionNotice, setSelectionNotice] = useState<string>();
  const inputRef = useRef<HTMLInputElement>(null);
  const selectionGeneration = useRef(0);

  useEffect(() => {
    selectionGeneration.current += 1;
    setFiles([]);
    setManifest(undefined);
    setTotalBytes(0);
    setHashing(false);
    setUploading(false);
    setError(undefined);
    setSelectionNotice(undefined);
    if (inputRef.current) inputRef.current.value = '';
    onCleared();
  }, [mode, onCleared]);

  function clearSelection() {
    selectionGeneration.current += 1;
    setFiles([]);
    setManifest(undefined);
    setTotalBytes(0);
    setHashing(false);
    setUploading(false);
    setError(undefined);
    setSelectionNotice(undefined);
    if (inputRef.current) inputRef.current.value = '';
    onCleared();
  }

  async function handleFiles(event: ChangeEvent<HTMLInputElement>) {
    const selected = Array.from(event.target.files ?? []);
    selectionGeneration.current += 1;
    const generation = selectionGeneration.current;
    setError(undefined);
    setSelectionNotice(undefined);
    onCleared();
    if (mode === 'archive') {
      if (selected.length !== 1 || !selected[0]) {
        setError(new ApiRequestError(422, '归档上传必须选择一个文件。', 'validation', 'invalid_upload'));
        setFiles([]);
        return;
      }
      try {
        validateArchiveFile(selected[0]);
        setFiles(selected);
        setTotalBytes(selected[0].size);
        setManifest(undefined);
        setSelectionNotice(`已选择 1 个归档文件，共 ${formatBytes(selected[0].size)}。`);
      } catch (reason) {
        setFiles([]);
        setError(reason);
        onError?.(reason);
      }
      return;
    }
    try {
      const summary = validateDirectoryFiles(selected);
      setFiles(selected);
      setTotalBytes(summary.totalBytes);
      setHashing(true);
      const result = await buildDirectoryManifest(selected);
      if (selectionGeneration.current !== generation) return;
      setManifest(result.manifest);
      setSelectionNotice(`已选择 ${selected.length} 个文件，共 ${formatBytes(result.totalBytes)}；SHA-256 已顺序计算。`);
    } catch (reason) {
      if (selectionGeneration.current !== generation) return;
      setFiles([]);
      setManifest(undefined);
      setTotalBytes(0);
      setError(reason);
      onError?.(reason);
    } finally {
      if (selectionGeneration.current === generation) setHashing(false);
    }
  }

  async function upload() {
    if (files.length === 0) {
      setError(new ApiRequestError(422, '请先选择上传内容。', 'validation', 'invalid_upload'));
      return;
    }
    if (mode === 'directory' && !manifest) {
      setError(new ApiRequestError(422, '目录 manifest 尚未准备好。', 'validation', 'invalid_upload'));
      return;
    }
    setUploading(true);
    setError(undefined);
    try {
      const result = await client.createSourceUpload(mode === 'archive'
        ? { mode: 'archive', archive: files[0] }
        : { mode: 'directory', files, manifest: manifest as SourceUploadManifest });
      if (result.status !== 'ready') throw new ApiRequestError(422, `上传状态为 ${result.status}，尚未可以创建应用。`, 'validation', 'upload_not_ready');
      setSelectionNotice(`上传完成：${result.fileCount} 个文件，共 ${formatBytes(result.bytes)}。`);
      onUploaded(result);
    } catch (reason) {
      setError(reason);
      onError?.(reason);
    } finally {
      setUploading(false);
    }
  }

  const busy = disabled || hashing || uploading;
  return (
    <section className="source-upload-field" aria-labelledby="source-upload-heading">
      <div className="source-upload-field__heading"><div><h3 id="source-upload-heading">安全上传</h3><p>浏览器只提交文件内容和规范化相对路径，不读取任意本地路径。</p></div></div>
      <div className="source-upload-field__modes" role="radiogroup" aria-label="上传类型">
        <button type="button" role="radio" aria-checked={mode === 'archive'} className={mode === 'archive' ? 'is-selected' : ''} onClick={() => setMode('archive')} disabled={busy}>单个归档</button>
        <button type="button" role="radio" aria-checked={mode === 'directory'} className={mode === 'directory' ? 'is-selected' : ''} onClick={() => setMode('directory')} disabled={busy}>文件夹目录</button>
      </div>
      <label className="source-upload-field__input-label" htmlFor="source-upload-input">{mode === 'archive' ? '选择 .zip / .tar.gz / .tgz' : '选择目录文件'}</label>
      <input ref={inputRef} id="source-upload-input" type="file" accept={mode === 'archive' ? '.zip,.tar.gz,.tgz' : undefined} multiple={mode === 'directory'} onChange={(event) => void handleFiles(event)} disabled={busy} {...(mode === 'directory' ? { webkitdirectory: '', directory: '' } : {})} />
      <p className="source-upload-field__hint">目录选择依赖浏览器的 <code>webkitdirectory</code> 和 <code>webkitRelativePath</code> 能力；不支持时请改用归档上传。目录 hash 按文件顺序计算，单文件不同时读入内存。</p>
      {files.length > 0 && <p className="source-upload-field__summary" role="status">当前选择：{files.length} 个文件 · {formatBytes(totalBytes)}{hashing ? ' · 正在计算 SHA-256…' : ''}</p>}
      {selectionNotice && <p className="source-upload-field__notice" role="status">{selectionNotice}</p>}
      {value && <dl className="source-upload-field__result"><div><dt>上传 ID</dt><dd>{value.uploadId}</dd></div><div><dt>服务端 digest</dt><dd>{value.digest}</dd></div><div><dt>服务端状态</dt><dd>{value.status}</dd></div></dl>}
      {Boolean(error) && <p className="source-upload-field__error" role="alert">{sourceUploadErrorMessage(error)}</p>}
      <div className="source-upload-field__actions"><button type="button" onClick={clearSelection} disabled={busy || (files.length === 0 && !value)}>清除选择</button><button type="button" onClick={() => void upload()} disabled={busy || files.length === 0}>{hashing ? '正在计算摘要…' : uploading ? '正在上传…' : value ? '重新上传' : '上传并生成来源'}</button></div>
    </section>
  );
}
