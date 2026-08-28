import {
  domainAccessStatusDefinition,
  domainAccessStatuses,
  type DomainAccessSnapshot,
  type DomainAccessStatus,
} from './domainAccess';

export interface DomainAccessStatusProps {
  snapshot: DomainAccessSnapshot;
  compact?: boolean;
}

function statusClassName(status: DomainAccessStatus): string {
  return `domain-access-status domain-access-status--${domainAccessStatusDefinition(status).tone}`;
}

/**
 * Present route facts as discrete states. This intentionally has no progress
 * bar or percentage: DNS, ACME and traffic switching are not linear progress.
 */
export function DomainAccessStatus({ snapshot, compact = false }: DomainAccessStatusProps) {
  const statuses = domainAccessStatuses(snapshot);

  return (
    <section className="domain-access" aria-label="应用访问状态" aria-live="polite">
      {statuses.map((status) => {
        const definition = domainAccessStatusDefinition(status);
        return (
          <div className={statusClassName(status)} key={status}>
            <strong>{definition.label}</strong>
            {!compact && <p>{definition.detail}</p>}
          </div>
        );
      })}
    </section>
  );
}
