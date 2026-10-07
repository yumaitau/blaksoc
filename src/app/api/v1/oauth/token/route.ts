import { clientIp, json, rateStore, shape, TOKEN_RATE } from "@/lib/api/http";
import { TokenResponse } from "@/lib/api/schemas";
import { parseClientCredentials } from "@/lib/api/tokens";
import { issueServiceToken } from "@/lib/services/service-identities";

export const dynamic = "force-dynamic";

const invalidClient = () => json(401, { error: "invalid_client" }, { "www-authenticate": 'Basic realm="blakSOC API"' });

/** OAuth 2.0 client_credentials grant (RFC 6749 §4.4) for service identities. */
export async function POST(req: Request) {
  if (!(req.headers.get("content-type") ?? "").toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return json(400, { error: "invalid_request", message: "send application/x-www-form-urlencoded" });
  }
  const text = await req.text();
  if (text.length > 4096) return json(400, { error: "invalid_request" });
  const body = new URLSearchParams(text);
  const grant = body.get("grant_type");
  if (!grant) return json(400, { error: "invalid_request", message: "grant_type is required" });
  if (grant !== "client_credentials") return json(400, { error: "unsupported_grant_type" });
  const creds = parseClientCredentials(req.headers.get("authorization"), body);
  if (!creds) return invalidClient();
  const rate = await rateStore().consume(`api-token:${creds.clientId}`, TOKEN_RATE);
  if (!rate.allowed) return json(429, { error: "rate_limited" }, { "retry-after": String(rate.retryAfter ?? TOKEN_RATE.window) });
  const issued = await issueServiceToken({ ...creds, ip: clientIp(req) });
  if (!issued) return invalidClient();
  return json(200, shape(TokenResponse, { access_token: issued.accessToken, token_type: "Bearer", expires_in: issued.expiresIn, scope: issued.scopes.join(" ") }), { pragma: "no-cache" });
}
