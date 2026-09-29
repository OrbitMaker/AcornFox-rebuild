export const PUBLIC_CSRF_COOKIE_NAME = "__Host-acornfox_csrf";
export const LOCAL_CSRF_COOKIE_NAME = "acornfox_local_csrf";
export const EXACT_LOCAL_ORIGIN = "http://127.0.0.1:8080";

/**
 * Checks whether an origin is an actual HTTP loopback origin.
 * Strictly requires http: protocol and a loopback host (127.0.0.0/8, localhost, or [::1]).
 * HTTPS origins (even on loopback) use host cookies and return false here.
 * Non-loopback hostnames or arbitrary forwarded headers are never trusted.
 */
export function isLoopbackOrigin(origin?: string): boolean {
  if (!origin) return false;
  try {
    const url = new URL(origin);
    if (url.protocol !== "http:") return false;
    const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1") {
      return true;
    }
    const parts = hostname.split(".");
    if (parts.length === 4 && parts[0] === "127") {
      return parts.every((p) => {
        const n = Number(p);
        return String(n) === p && n >= 0 && n <= 255;
      });
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Resolves the CSRF token based on current origin.
 * Strictly uses LOCAL_CSRF_COOKIE_NAME only when current origin is an actual HTTP loopback origin.
 * In all other cases (including any public origin, HTTPS origin, or non-loopback host),
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
  const isLocalOrigin = isLoopbackOrigin(locationRef?.origin);
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
