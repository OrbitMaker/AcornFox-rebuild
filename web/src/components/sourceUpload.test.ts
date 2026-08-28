import { ApiRequestError } from '../api/errors';
import { buildDirectoryManifest, formatBytes, isSupportedArchive, sourceUploadErrorMessage, validateArchiveFile, validateDirectoryFiles } from './sourceUpload';

function fakeFile(name: string, content = 'content'): File {
  const file = new Blob([content], { type: 'text/plain' }) as File;
  Object.defineProperty(file, 'name', { configurable: true, value: name });
  Object.defineProperty(file, 'webkitRelativePath', { configurable: true, value: name });
  return file;
}

describe('source upload browser helpers', () => {
  it('accepts exactly the supported archive extensions', () => {
    expect(isSupportedArchive('bundle.zip')).toBe(true);
    expect(isSupportedArchive('bundle.TAR.GZ')).toBe(true);
    expect(isSupportedArchive('bundle.tgz')).toBe(true);
    expect(isSupportedArchive('bundle.rar')).toBe(false);
    expect(() => validateArchiveFile(fakeFile('bundle.rar'))).toThrowError(ApiRequestError);
    expect(formatBytes(1024 * 1024)).toBe('1.0 MiB');
  });

  it.each(['/absolute/file', 'C:/absolute/file', 'src\\file', 'src/../file', 'src/./file', 'src//file', 'src/'])('rejects unsafe directory path %s', (path) => {
    const file = fakeFile(path || 'file');
    Object.defineProperty(file, 'webkitRelativePath', { configurable: true, value: path });
    expect(() => validateDirectoryFiles([file])).toThrowError(ApiRequestError);
  });

  it('rejects duplicate paths and oversized files before upload', () => {
    const first = fakeFile('src/app.js');
    const duplicate = fakeFile('src/app.js');
    expect(() => validateDirectoryFiles([first, duplicate])).toThrowError(/重复路径/);
    const oversized = fakeFile('large.bin');
    Object.defineProperty(oversized, 'size', { configurable: true, value: 32 * 1024 * 1024 + 1 });
    expect(() => validateDirectoryFiles([oversized])).toThrowError(/单文件/);
  });

  it('hashes directory files sequentially and emits the server manifest shape', async () => {
    const first = fakeFile('src/first.txt', 'hello');
    const second = fakeFile('src/second.txt', 'world');
    const result = await buildDirectoryManifest([first, second]);

    expect(result.totalBytes).toBe(first.size + second.size);
    expect(result.manifest.files.map((file) => file.path)).toEqual(['src/first.txt', 'src/second.txt']);
    expect(result.manifest.files[0]?.digest).toBe('sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    expect(result.manifest.files[1]?.digest).toBe('sha256:486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7');
  });

  it.each([
    [413, 'size', '上传内容超过限制。'],
    [422, 'validation', '上传内容未通过校验。'],
    [503, 'unavailable', '上传服务暂时不可用。'],
  ] as const)('keeps server upload failure %s safe', (status, kind, message) => {
    expect(sourceUploadErrorMessage(new ApiRequestError(status, message, kind))).toBe(message);
  });
});
