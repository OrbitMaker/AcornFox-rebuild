import { Tag } from '@douyinfe/semi-ui';
import {
  PUBLISHING_STATUS_DESCRIPTIONS,
  PUBLISHING_STATUS_LABELS,
  PUBLISHING_STATUSES,
  type PublishingSnapshot,
  type PublishingStatus,
} from '../domain/publishing';

interface PublishingStatusProps {
  snapshot?: PublishingSnapshot;
  compact?: boolean;
}
const statusTone: Record<PublishingStatus, 'blue' | 'amber' | 'green' | 'red'> = {
  preparing: 'blue',
  building: 'amber',
  deploying: 'blue',
  succeeded: 'green',
  failed: 'red',
};

function currentIndex(status: PublishingStatus): number {
  return PUBLISHING_STATUSES.indexOf(status);
}

export function PublishingStatusTag({ snapshot, compact = false }: PublishingStatusProps) {
  const status = snapshot?.status ?? 'preparing';
  return (
    <Tag color={statusTone[status]} size={compact ? 'small' : 'default'}>
      {PUBLISHING_STATUS_LABELS[status]}
    </Tag>
  );
}

export function PublishingStatusTrack({ snapshot }: PublishingStatusProps) {
  const status = snapshot?.status ?? 'preparing';
  const activeIndex = currentIndex(status);
  return (
    <div className="status-track" aria-label={`发布状态：${PUBLISHING_STATUS_LABELS[status]}`}>
      {PUBLISHING_STATUSES.map((item, index) => {
        const completed = index < activeIndex && status !== 'failed';
        const active = item === status;
        return (
          <div className={`status-track__step ${completed ? 'is-complete' : ''} ${active ? 'is-active' : ''} ${active && status === 'failed' ? 'is-failed' : ''}`} key={item}>
            <span className="status-track__dot" aria-hidden="true">{completed ? '✓' : index + 1}</span>
            <span className="status-track__label">{PUBLISHING_STATUS_LABELS[item]}</span>
            {index < PUBLISHING_STATUSES.length - 1 && <span className="status-track__line" aria-hidden="true" />}
          </div>
        );
      })}
      <p className="status-track__description">{PUBLISHING_STATUS_DESCRIPTIONS[status]}</p>
    </div>
  );
}
