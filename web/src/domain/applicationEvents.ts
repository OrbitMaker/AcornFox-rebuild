import { applyPublishingEvent, createPublishingSnapshot, type PublishEvent } from './publishing';
import type { ApplicationSummary } from '../api/types';

export function updateFromPublishEvent(applications: ApplicationSummary[], event: PublishEvent): ApplicationSummary[] {
  return applications.map((application) => {
    if (application.id !== event.applicationId && application.operationId !== event.operationId) return application;
    return {
      ...application,
      publishing: applyPublishingEvent(application.publishing ?? createPublishingSnapshot(), event),
      updatedAt: event.occurredAt,
    };
  });
}
