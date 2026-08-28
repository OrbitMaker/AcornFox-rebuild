import { ApiRequestError, classifyStatus, createNetworkError, createResponseError, createTimeoutError } from './errors';

describe('API error model', () => {
  it.each([
    [401, 'auth'],
    [409, 'conflict'],
    [413, 'size'],
    [415, 'media'],
    [422, 'validation'],
    [429, 'rate'],
    [503, 'unavailable'],
    [500, 'unavailable'],
  ] as const)('classifies HTTP %s as %s', (status, kind) => {
    expect(classifyStatus(status)).toBe(kind);
  });

  it('retains only the safe response code and message', () => {
    const error = createResponseError(409, 'fallback', { code: 'domain_conflict', message: '域名状态冲突', secret: 'must-not-survive' });

    expect(error).toMatchObject({ status: 409, kind: 'conflict', code: 'domain_conflict', message: '域名状态冲突' });
    expect((error as unknown as { secret?: string }).secret).toBeUndefined();
  });

  it('provides stable timeout and network errors without a response body', () => {
    expect(createTimeoutError()).toMatchObject({ kind: 'timeout', code: 'request_timeout', status: undefined });
    expect(createNetworkError()).toMatchObject({ kind: 'network', code: 'network_error', status: undefined });
    expect(new ApiRequestError(422, 'invalid', 'validation', 'invalid_input')).toMatchObject({ kind: 'validation', code: 'invalid_input' });
  });
});
