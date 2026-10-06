/**
 * Why a connection URL will not authenticate as `role` with `password`, or null when it will.
 * A password with URL delimiters (#, @, /, ?, %) must be percent-encoded inside the URL; a raw
 * one is silently cut short, and the migration would set a password the app can never send.
 */
export function urlPasswordMismatch(name: string, url: string, role: string, password: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return `${name} is not a valid URL (percent-encode a password containing #, @, / or ?)`;
  }
  if (decodeURIComponent(parsed.username) !== role) return `${name} must connect as ${role}`;
  let inUrl: string;
  try {
    inUrl = decodeURIComponent(parsed.password);
  } catch {
    return `${name} has a malformed percent-encoded password`;
  }
  if (inUrl !== password) return `${name} password does not match the role password; percent-encode it in the URL (encodeURIComponent) or use a URL-safe password such as openssl rand -hex 32`;
  return null;
}
