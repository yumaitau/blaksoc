/**
 * The user and password postgres.js will send for a connection URL. Mirrors `parseUrl` in
 * postgres/src/index.js (multi-host URLs use the first host), so this check is never stricter
 * than the driver. Throws when the driver would also fail to parse the URL.
 */
function driverCredentials(url: string): { username: string; password: string } {
  let host = url.slice(url.indexOf("://") + 3).split(/[?/]/)[0]!;
  host = decodeURIComponent(host.slice(host.indexOf("@") + 1));
  const parsed = new URL(url.replace(host, host.split(",")[0]!));
  return { username: decodeURIComponent(parsed.username), password: decodeURIComponent(parsed.password) };
}

/**
 * Why a connection URL will not authenticate as `role` with `password`, or null when it will.
 * A password with URL delimiters (#, /, ?, %) must be percent-encoded inside the URL; a raw one is
 * cut short, and the migration would set a password the app can never send. A URL without a user
 * or password leaves them to PGUSER / PGPASSWORD, which this check cannot see, so it passes.
 */
export function urlPasswordMismatch(name: string, url: string, role: string, password: string): string | null {
  let creds: { username: string; password: string };
  try {
    creds = driverCredentials(url);
  } catch {
    return `${name} is not a valid connection URL (percent-encode a password containing #, /, ? or %)`;
  }
  if (creds.username && creds.username !== role) return `${name} must connect as ${role}`;
  if (creds.password && creds.password !== password) return `${name} password does not match the role password; percent-encode it in the URL (encodeURIComponent) or use a URL-safe password such as openssl rand -hex 32`;
  return null;
}
