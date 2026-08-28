import type { ApplicationSummary } from '../api/types';

export function applicationIdFromLocation(location: Pick<Location, 'search'> | undefined): string | undefined {
  if (!location) return undefined;
  const value = new URLSearchParams(location.search).get('application')?.trim();
  return value || undefined;
}

export function resolveSelectedApplicationId(requestedId: string | undefined, applications: readonly ApplicationSummary[]): string | undefined {
  return requestedId && applications.some((application) => application.id === requestedId) ? requestedId : undefined;
}

export function setApplicationQuery(applicationId: string | undefined): void {
  if (typeof window === 'undefined' || !window.history?.replaceState) return;
  const url = new URL(window.location.href);
  url.search = '';
  if (applicationId) url.searchParams.set('application', applicationId);
  window.history.replaceState(window.history.state, '', url);
}
