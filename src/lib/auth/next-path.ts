/**
 * Same-origin path to send a user to after sign-in, or "/". Browsers read `\` as `/` and drop tabs
 * and newlines, so `/\evil.example` or `/\t/evil.example` would otherwise leave the site.
 */
export function safeNextPath(next: unknown): string {
  if (typeof next !== "string" || !next.startsWith("/") || /[\\\u0000-\u001f\u007f]/.test(next)) return "/";
  const base = "http://blaksoc.invalid";
  try {
    const url = new URL(next, base);
    // Returning to authentication would restart the automatic flow indefinitely.
    const pathname = decodeURIComponent(url.pathname);
    if (/^\/(?:login|api\/auth)(?:\/|$)/.test(pathname)) return "/";
    return url.origin === base ? `${url.pathname}${url.search}${url.hash}` : "/";
  } catch {
    return "/";
  }
}
