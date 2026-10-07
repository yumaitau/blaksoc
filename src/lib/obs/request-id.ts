/** Header that carries the correlation id from the edge, through the web app, into worker jobs. */
export const REQUEST_ID_HEADER = "x-request-id";

// An upstream id (ingress, load balancer) is kept only if it is a plain token, so it cannot inject into log lines.
const VALID = /^[A-Za-z0-9._:-]{8,128}$/;

/** The caller's id when it is well formed, otherwise a new one. Pure, so the proxy can use it. */
export function requestIdFrom(headers: Pick<Headers, "get">): string {
  const inbound = headers.get(REQUEST_ID_HEADER);
  return inbound && VALID.test(inbound) ? inbound : crypto.randomUUID();
}
