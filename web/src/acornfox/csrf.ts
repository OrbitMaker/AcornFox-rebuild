export const PUBLIC_CSRF_COOKIE_NAME = "__Host-acornfox_csrf";
export const LOCAL_CSRF_COOKIE_NAME = "acornfox_local_csrf";
export const EXACT_LOCAL_ORIGIN = "http://127.0.0.1:8080";

/**
 * Resolves the CSRF token based on current origin.
 * Strictly uses LOCAL_CSRF_COOKIE_NAME only when current origin is exactly http://127.0.0.1:8080.
 * In all other cases (including any public origin or non-exact local address),
 * it uses PUBLIC_CSRF_COOKIE_NAME and never falls back to local cookie.
 */
export function resolveCsrfToken(
  documentRef: { cookie: string } | undefined = typeof document !== "undefined"
    ? document
    : undefined,
  locationRef: { origin?: string } | undefined = typeof window !== "undefined"
    ? window.location
    : undefined,
): string | undefined {
  if (!documentRef) return undefined;
  const isLocalOrigin = locationRef?.origin === EXACT_LOCAL_ORIGIN;
  const targetCookieName = isLocalOrigin
    ? LOCAL_CSRF_COOKIE_NAME
    : PUBLIC_CSRF_COOKIE_NAME;
  const prefix = `${targetCookieName}=`;

  const entry = documentRef.cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(prefix));

  if (!entry) return undefined;
  try {
    return decodeURIComponent(entry.slice(prefix.length));
  } catch {
    return undefined;
  }
}
