import { useState } from 'react';
import { IconArrowLeft, IconArrowRight, IconCheckCircleStroked } from '@douyinfe/semi-icons';
import { Button, Card, Input, Radio, Steps, Toast } from '@douyinfe/semi-ui';
import type { ApiClient } from '../api/types';
import type { CreateApplicationInput, SourceKind } from '../api/types';

interface CreateApplicationWizardProps {
  client: ApiClient;
  onCancel: () => void;
  onCreated: (operationId: string) => void;
}

const sourceOptions: Array<{ value: SourceKind; label: string; description: string }> = [
  { value: 'git', label: 'Git 仓库', description: '标准 HTTPS 或 SSH 地址，固定到一次来源版本。' },
  { value: 'folder', label: '文件夹上传', description: '用于本地代码目录，上传后生成不可变来源版本。' },
  { value: 'archive', label: '归档上传', description: '支持 .zip、.tar.gz 和 .tgz，解压前执行安全校验。' },
];

export function CreateApplicationWizard({ client, onCancel, onCreated }: CreateApplicationWizardProps) {
  const [step, setStep] = useState(0);
  const [name, setName] = useState('');
  const [sourceKind, setSourceKind] = useState<SourceKind>('git');
  const [locator, setLocator] = useState('');
  const [branch, setBranch] = useState('main');
  const [submitting, setSubmitting] = useState(false);

  const selectedSource = sourceOptions.find((option) => option.value === sourceKind) ?? sourceOptions[0];
  const canAdvance = step === 0 ? name.trim().length >= 2 : locator.trim().length > 0;

  const submit = async () => {
    setSubmitting(true);
    try {
      const input: CreateApplicationInput = {
        name: name.trim(),
        source: { kind: sourceKind, locator: locator.trim(), ref: sourceKind === 'git' ? branch.trim() || 'main' : undefined },
      };
      const result = await client.createApplication(input);
      Toast.success('应用已创建，发布任务开始准备');
      onCreated(result.operationId);
    } catch (error) {
      Toast.error(error instanceof Error ? error.message : '创建应用失败');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="page-section wizard-page" aria-labelledby="create-heading">
      <header className="section-heading">
        <div>
          <button className="back-link" type="button" onClick={onCancel}><IconArrowLeft /> 返回应用列表</button>
          <p className="eyebrow">创建应用</p>
          <h1 id="create-heading">接入代码来源</h1>
          <p className="section-subtitle">先固定来源版本，再生成交付定义。AI 不参与这条 Golden Path。</p>
        </div>
      </header>

      <div className="wizard-layout">
        <aside className="wizard-aside">
          <Steps current={step} direction="vertical">
            <Steps.Step title="基本信息" description="给应用一个清晰的名称" />
            <Steps.Step title="代码来源" description="Git 或安全上传" />
            <Steps.Step title="确认摘要" description="创建后进入发布状态流" />
          </Steps>
          <div className="boundary-note">
            <span className="boundary-note__mark"><IconCheckCircleStroked /></span>
            <div><strong>自部署单机边界</strong><p>应用会进入当前实例预设节点，不提供云节点或多租户选择。</p></div>
          </div>
        </aside>

        <Card className="wizard-card" bordered={false}>
          {step === 0 && (
            <div className="wizard-panel">
              <div className="wizard-panel__intro"><span className="step-number">01</span><div><h2>应用叫什么？</h2><p>名称用于控制台展示，创建后仍可在设置中调整显示名。</p></div></div>
              <label className="plain-field"><span>应用名称</span><Input placeholder="例如：团队知识库" value={name} onChange={(value) => setName(String(value))} showClear /></label>
              <div className="form-hint">建议使用团队成员能直接理解的名称，不要包含密钥或环境变量。</div>
            </div>
          )}
          {step === 1 && (
            <div className="wizard-panel">
              <div className="wizard-panel__intro"><span className="step-number">02</span><div><h2>代码从哪里来？</h2><p>来源会被固化成不可变的 SourceRevision，重复发布不会漂移。</p></div></div>
              <div className="source-picker" role="radiogroup" aria-label="代码来源类型">
                {sourceOptions.map((option) => (
                  <button className={`source-option ${sourceKind === option.value ? 'is-selected' : ''}`} type="button" key={option.value} onClick={() => setSourceKind(option.value)} role="radio" aria-checked={sourceKind === option.value}>
                    <Radio checked={sourceKind === option.value} />
                    <span><strong>{option.label}</strong><small>{option.description}</small></span>
                  </button>
                ))}
              </div>
              <label className="plain-field"><span>{sourceKind === 'git' ? '仓库地址' : '文件路径或归档名'}</span><Input placeholder={sourceKind === 'git' ? 'https://git.example.com/team/app.git' : '选择文件后显示名称'} value={locator} onChange={(value) => setLocator(String(value))} showClear /></label>
              {sourceKind === 'git' && <label className="plain-field"><span>分支或 ref</span><Input placeholder="main" value={branch} onChange={(value) => setBranch(String(value))} /></label>}
              <div className="form-hint">{selectedSource.description}</div>
            </div>
          )}
          {step === 2 && (
            <div className="wizard-panel">
              <div className="wizard-panel__intro"><span className="step-number">03</span><div><h2>确认创建</h2><p>确认后会创建应用和一次发布 Operation，状态由事件推进。</p></div></div>
              <dl className="review-list">
                <div><dt>应用名称</dt><dd>{name}</dd></div>
                <div><dt>代码来源</dt><dd>{selectedSource.label}</dd></div>
                <div><dt>定位信息</dt><dd>{locator}</dd></div>
                {sourceKind === 'git' && <div><dt>分支 / ref</dt><dd>{branch || 'main'}</dd></div>}
                <div><dt>部署位置</dt><dd>当前实例预设单机</dd></div>
              </dl>
              <div className="review-note"><strong>接下来会发生什么</strong><p>控制面会依次显示准备中、构建中、部署中、部署成功或部署失败。每次成功都需要独立验证和证据。</p></div>
            </div>
          )}
          <footer className="wizard-actions">
            <Button theme="borderless" onClick={step === 0 ? onCancel : () => setStep((value) => value - 1)} icon={step === 0 ? undefined : <IconArrowLeft />}> {step === 0 ? '取消' : '上一步'}</Button>
            {step < 2 ? <Button theme="solid" type="primary" disabled={!canAdvance} onClick={() => setStep((value) => value + 1)} icon={<IconArrowRight />}>下一步</Button> : <Button theme="solid" type="primary" loading={submitting} onClick={submit}>创建并开始发布</Button>}
          </footer>
        </Card>
      </div>
    </section>
  );
}
