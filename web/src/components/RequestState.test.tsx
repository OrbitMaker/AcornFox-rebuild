import { renderToStaticMarkup } from 'react-dom/server';
import { ApiRequestError } from '../api/errors';
import { RequestState, requestStateMessage } from './RequestState';

describe('RequestState', () => {
  it.each([
    ['conflict', '状态已发生变化'],
    ['validation', '提交信息未通过校验'],
    ['rate', '请求过于频繁'],
    ['unavailable', '控制面暂时不可用'],
    ['timeout', '请求超时'],
    ['network', '网络请求未完成'],
  ] as const)('maps %s to a safe user message', (kind, message) => {
    expect(requestStateMessage(new ApiRequestError(500, 'server detail', kind))).toContain(message);
  });

  it('renders loading and retry semantics accessibly', () => {
    const loading = renderToStaticMarkup(<RequestState loading />);
    const error = renderToStaticMarkup(<RequestState error={new ApiRequestError(409, 'conflict', 'conflict')} onRetry={() => undefined} />);

    expect(loading).toContain('role="status"');
    expect(error).toContain('role="alert"');
    expect(error).toContain('重试');
  });
});
