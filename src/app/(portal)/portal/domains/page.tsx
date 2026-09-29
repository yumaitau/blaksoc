import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { domainBoard } from "@/lib/services/surface";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Domains" };

const inputCls = "mt-1 w-full min-h-11 rounded-md border border-border bg-transparent px-3 text-base";

const ERRORS: Record<string, string> = {
  domain: "Enter a domain like example.org.",
  missing: "That domain is not on this organisation.",
  unverified: "Verify the domain before checking breaches.",
  unattested: "Attest ownership before a scan.",
  denied: "Your role cannot change domains.",
  generic: "That did not save. Try again.",
};

export default async function DomainsPage({ searchParams }: { searchParams: Promise<{ error?: string; ok?: string }> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const ws = await currentWorkspace(ctx);
  const candidates = ctx.tenants.filter((tenant) => tenant.kind === "customer" && can(ctx, "vuln:read", tenant.id));
  const tenant = candidates.find((item) => item.id === ws.tenant?.id) ?? candidates[0];
  if (!tenant) {
    return (
      <div>
        <h1 className="text-xl font-semibold">Domains</h1>
        <p className="mt-2 text-sm text-muted">Your role cannot view domain checks.</p>
      </div>
    );
  }
  const board = await domainBoard(ctx, tenant.id);
  const allow = can(ctx, "response:approve", tenant.id);
  const latest = new Map<string, { score: number; checkedAt: Date }>();
  for (const check of board.checks) {
    if (!latest.has(check.domainId)) latest.set(check.domainId, { score: check.score, checkedAt: check.checkedAt });
  }
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Domains</h1>
        <p className="mt-2 text-sm">Email checks and outside-in notes for domains this organisation owns. Adding a name here does not register it with a registrar.</p>
        {sp.error ? <p className="mt-2 text-sm" role="alert">{ERRORS[sp.error] ?? ERRORS.generic}</p> : null}
        {sp.ok ? <p className="mt-2 text-sm">Saved.</p> : null}
      </header>

      {allow ? (
        <form className="space-y-2" action="/portal/domains/save" method="post">
          <input type="hidden" name="intent" value="add" />
          <label className="block text-sm" htmlFor="domain-name">Add a domain</label>
          <input className={inputCls} id="domain-name" name="name" autoComplete="off" required />
          <button className="inline-flex min-h-11 items-center rounded-md border border-border px-3" type="submit">Add domain</button>
        </form>
      ) : null}

      {board.domains.length === 0 ? <p className="text-sm text-muted">No domains yet.</p> : null}

      {board.domains.map((domain) => {
        const score = latest.get(domain.id);
        return (
          <section key={domain.id} className="space-y-3 border-t border-border pt-4">
            <h2 className="text-lg font-semibold">{domain.name}</h2>
            <p className="text-sm">Score: {score ? score.score : "not checked yet"}</p>
            <p className="text-sm text-muted">Verification token: {domain.verificationToken}</p>
            <p className="text-sm">{domain.verifiedAt ? "Verified." : "Not verified."} {domain.attestedAt ? "Ownership attested." : "Ownership not attested."}</p>
            {allow ? (
              <>
                <form className="space-y-2" action="/portal/domains/save" method="post">
                  <input type="hidden" name="intent" value="verify" />
                  <input type="hidden" name="domainId" value={domain.id} />
                  <label className="block text-sm" htmlFor={`txt-${domain.id}`}>TXT records you published</label>
                  <textarea className={inputCls} id={`txt-${domain.id}`} name="txt" rows={3} />
                  <button className="inline-flex min-h-11 items-center rounded-md border border-border px-3" type="submit">Verify</button>
                </form>
                <form className="space-y-2" action="/portal/domains/save" method="post">
                  <input type="hidden" name="intent" value="check" />
                  <input type="hidden" name="domainId" value={domain.id} />
                  <label className="block text-sm" htmlFor={`spf-${domain.id}`}>SPF records, one per line</label>
                  <textarea className={inputCls} id={`spf-${domain.id}`} name="spf" rows={2} />
                  <label className="block text-sm" htmlFor={`dmarc-${domain.id}`}>DMARC record</label>
                  <textarea className={inputCls} id={`dmarc-${domain.id}`} name="dmarc" rows={2} />
                  <label className="block text-sm" htmlFor={`dkim-${domain.id}`}>DKIM lines as name then value</label>
                  <textarea className={inputCls} id={`dkim-${domain.id}`} name="dkim" rows={2} />
                  <label className="block text-sm" htmlFor={`extra-${domain.id}`}>MTA-STS, TLS-RPT, or BIMI lines as name then value</label>
                  <textarea className={inputCls} id={`extra-${domain.id}`} name="extras" rows={2} />
                  <button className="inline-flex min-h-11 items-center rounded-md border border-border px-3" type="submit">Check email posture</button>
                </form>
                <form action="/portal/domains/save" method="post">
                  <input type="hidden" name="intent" value="attest" />
                  <input type="hidden" name="domainId" value={domain.id} />
                  <button className="inline-flex min-h-11 items-center rounded-md border border-border px-3" type="submit">Attest ownership before scanning</button>
                </form>
                <form action="/portal/domains/save" method="post">
                  <input type="hidden" name="intent" value="exposure" />
                  <input type="hidden" name="domainId" value={domain.id} />
                  <button className="inline-flex min-h-11 items-center rounded-md border border-border px-3" type="submit">Check credential exposure</button>
                </form>
              </>
            ) : null}
          </section>
        );
      })}

      <section className="space-y-2 border-t border-border pt-4">
        <h2 className="text-lg font-semibold">Score history</h2>
        {board.checks.length === 0 ? <p className="text-sm text-muted">No checks yet.</p> : null}
        <ul className="space-y-1 text-sm">
          {board.checks.map((check) => (
            <li key={check.id}>{check.checkedAt.toISOString().slice(0, 16).replace("T", " ")} score {check.score}</li>
          ))}
        </ul>
      </section>

      <section className="space-y-2 border-t border-border pt-4">
        <h2 className="text-lg font-semibold">DMARC reports</h2>
        {allow ? (
          <form className="space-y-2" action="/portal/domains/save" method="post" encType="multipart/form-data">
            <input type="hidden" name="intent" value="dmarc" />
            <label className="block text-sm" htmlFor="dmarc-file">Aggregate report (.xml, .gz, or .zip)</label>
            <input className={inputCls} id="dmarc-file" name="file" type="file" required />
            <button className="inline-flex min-h-11 items-center rounded-md border border-border px-3" type="submit">Upload report</button>
          </form>
        ) : null}
        <ul className="space-y-1 text-sm">
          {board.reports.map((report) => (
            <li key={report.id}>{report.domainName}: {report.summary.pass} passed, {report.summary.fail} failed, {report.summary.unknownSenders} unknown senders</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
