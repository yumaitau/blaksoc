import { egressFetch } from "@/lib/net/egress";
/**
 * Minimal client for the Kelpie case management REST API (`/api/v1`).
 * Mirrors the contract of `@kelpie/sdk` (github.com/yumaitau/Kelpie, packages/sdk) for the calls blakSOC makes.
 * The token is a server-side `klp_*` token. Its organisation is the customer's Kelpie organisation.
 */

export const KELPIE_STATUSES = ["open", "in_progress", "contained", "eradicated", "recovered", "closed"] as const;
export type KelpieStatus = (typeof KELPIE_STATUSES)[number];
export type KelpieSeverity = "low" | "medium" | "high" | "critical";
export type KelpieTlp = "clear" | "green" | "amber" | "amber_strict" | "red";
export type KelpieObservableType = "ip" | "domain" | "url" | "file_hash" | "email" | "hostname" | "username" | "other";

export type KelpieCreateCase = {
  title: string;
  summary?: string;
  severity?: KelpieSeverity;
  tlp?: KelpieTlp;
  classification?: "malware" | "phishing" | "unauthorised_access" | "data_breach" | "dos" | "policy_violation" | "other";
  occurredAt?: string | null;
  detectedAt?: string | null;
  tags?: string[];
  sourceSystem: string;
  sourceReference: string;
  sourceUrl?: string;
};

export type KelpieCreated = { id: string; caseNumber: string; created: boolean };

/** The fields blakSOC reads back. Kelpie returns more. */
export type KelpieCase = {
  id: string;
  caseNumber: string;
  title: string;
  status: KelpieStatus;
  severity: KelpieSeverity;
  version: number;
  closedAt: string | null;
  updatedAt: string;
};

export class KelpieError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "KelpieError";
  }
  /** 4xx other than 408/429 will not succeed on retry with the same input. */
  get permanent(): boolean {
    return this.status >= 400 && this.status < 500 && this.status !== 408 && this.status !== 429;
  }
}

export type KelpieFetch = (url: string, init: { method: string; headers: Record<string, string>; body?: string; signal: AbortSignal }) => Promise<{ status: number; text(): Promise<string> }>;

const redact = (s: string) => s.replace(/klp_[A-Za-z0-9_-]+/g, "[redacted]").replace(/Bearer\s+\S+/gi, "Bearer [redacted]");

export class KelpieClient {
  private readonly base: string;
  constructor(baseUrl: string, private readonly token: string, private readonly doFetch: KelpieFetch = (url, init) => egressFetch(url, init, "internal")) {
    this.base = baseUrl.replace(/\/+$/, "");
  }

  caseUrl(id: string): string {
    return `${this.base}/cases/${encodeURIComponent(id)}`;
  }

  private async request<T>(method: string, path: string, body?: unknown, ok: number[] = [200, 201]): Promise<T> {
    const res = await this.doFetch(`${this.base}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.token}`, accept: "application/json", ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(20_000),
    });
    const text = await res.text();
    if (!ok.includes(res.status)) throw new KelpieError(`Kelpie ${method} ${path} returned ${res.status}: ${redact(text.slice(0, 200))}`, res.status);
    return (text ? JSON.parse(text) : {}) as T;
  }

  /** 201 is a new case, 200 an idempotent replay of the same (sourceSystem, sourceReference). */
  createCase(input: KelpieCreateCase): Promise<KelpieCreated> {
    return this.request<KelpieCreated>("POST", "/api/v1/cases", input);
  }

  getCase(id: string): Promise<KelpieCase> {
    return this.request<KelpieCase>("GET", `/api/v1/cases/${encodeURIComponent(id)}`);
  }

  addComment(caseId: string, body: string): Promise<{ id: string }> {
    return this.request<{ id: string }>("POST", `/api/v1/cases/${encodeURIComponent(caseId)}/comments`, { body });
  }

  /** Raise (or set) a case's severity with the reason shown in Kelpie. */
  updateSeverity(caseId: string, severity: KelpieSeverity, justification: string) {
    return this.request<unknown>("PATCH", `/api/v1/cases/${encodeURIComponent(caseId)}`, { severity, severityJustification: justification });
  }

  /** Proves the token reaches its organisation with cases:read. */
  async health(): Promise<{ ok: boolean; latencyMs: number; detail: Record<string, unknown>; error?: string }> {
    const start = Date.now();
    try {
      await this.request<unknown>("GET", "/api/v1/cases?limit=1");
      return { ok: true, latencyMs: Date.now() - start, detail: { baseUrl: this.base } };
    } catch (err) {
      return { ok: false, latencyMs: Date.now() - start, detail: { baseUrl: this.base }, error: err instanceof Error ? err.message : "unreachable" };
    }
  }

  addObservable(caseId: string, o: { type: KelpieObservableType; value: string; description?: string; isIoc?: boolean }): Promise<{ id: string }> {
    return this.request<{ id: string }>("POST", `/api/v1/cases/${encodeURIComponent(caseId)}/observables`, o);
  }
}
