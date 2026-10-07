import { CLOCK_KINDS, CLOCK_RULES, CLOCK_ZONES, HOUR_MS, formatZoned } from "@/lib/obligations/clock";
import { CLOCK_INFO, NOT_ADVICE, NOT_LAWYER_REVIEWED, clockApplies } from "@/lib/obligations/model";
import type { getObligation } from "@/lib/services/obligations";

const inputCls = "mt-1 w-full min-h-11 rounded-md border border-border bg-transparent px-3 text-base";
const buttonCls = "inline-flex min-h-11 items-center rounded-md border border-border px-4 text-sm";

type View = NonNullable<Awaited<ReturnType<typeof getObligation>>>;
type Clock = View["clocks"][number];

function state(clock: Clock, now: Date) {
  if (clock.reportedAt) return `Marked reported by ${clock.reportedBy ?? "unknown"} at ${formatZoned(clock.reportedAt, clock.timeZone)}${clock.reportRef ? `, reference ${clock.reportRef}` : ""}.`;
  const left = clock.dueAt.getTime() - now.getTime();
  if (left <= 0) return "Deadline passed. Not marked reported.";
  const hours = Math.floor(left / HOUR_MS);
  const minutes = Math.floor((left % HOUR_MS) / 60_000);
  return `${hours} h ${minutes} min left. Not marked reported.`;
}

/** SOCI and ransomware payment clocks. They hang off the obligations case because the applicability answers live there. */
export function ReportingClocks({ incidentId, view, canWrite }: { incidentId: string; view: View; canWrite: boolean }) {
  const action = `/portal/incidents/${incidentId}/obligations/save`;
  const now = new Date();
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold">SOCI and ransomware payment clocks</h3>
      <p className="text-sm text-muted">{NOT_LAWYER_REVIEWED} blakSOC does not report to the ASD. Each clock reminds through the escalation steps for this severity until you mark it reported.</p>
      {CLOCK_KINDS.map((kind) => {
        const info = CLOCK_INFO[kind];
        const clock = view.clocks.find((row) => row.kind === kind);
        return (
          <article key={kind} className="space-y-2">
            <h4 className="text-sm font-semibold">{info.label}</h4>
            <p className="text-sm text-muted">{info.act}. {info.basis}</p>
            {clock ? (
              <>
                <p className="text-sm">Started {formatZoned(clock.startedAt, clock.timeZone)} by {clock.startedBy}. Due {formatZoned(clock.dueAt, clock.timeZone)}.</p>
                <p className="text-sm" role="status">{state(clock, now)}</p>
                {clock.reminders.length ? (
                  <ul className="space-y-1 text-sm">
                    {clock.reminders.map((row) => <li key={`${row.key}-${row.at}`}>Hour {row.key}: {row.status} by {row.channel} to {row.destination} at {row.at.slice(0, 16)} UTC.</li>)}
                  </ul>
                ) : <p className="text-sm text-muted">No reminder sent yet. Reminders are due at hours {CLOCK_RULES[kind].reminders.join(", ")}.</p>}
                {canWrite ? (
                  <div className="flex flex-wrap items-end gap-3">
                    <form action={action} method="post">
                      <input type="hidden" name="intent" value="draft" />
                      <input type="hidden" name="kind" value={kind} />
                      <button className={buttonCls} type="submit">Save draft report</button>
                    </form>
                    {!clock.reportedAt ? (
                      <form className="flex flex-wrap items-end gap-3" action={action} method="post">
                        <input type="hidden" name="intent" value="reported" />
                        <input type="hidden" name="kind" value={kind} />
                        <label className="block text-sm">Report reference, if you have one
                          <input className={inputCls} name="reference" maxLength={120} />
                        </label>
                        <button className={buttonCls} type="submit">Mark as reported</button>
                      </form>
                    ) : null}
                  </div>
                ) : null}
              </>
            ) : !clockApplies(kind, view.case.applicability) ? (
              <p className="text-sm text-muted">Not started. The applicability answers say this duty does not apply. Change the answers if that is wrong.</p>
            ) : canWrite ? (
              <form className="space-y-3" action={action} method="post">
                <input type="hidden" name="intent" value="clock" />
                <input type="hidden" name="kind" value={kind} />
                <label className="block text-sm">{info.started}
                  <input className={inputCls} name="startedAt" type="datetime-local" required />
                </label>
                <label className="block text-sm">Time zone of that time
                  <select className={inputCls} name="timeZone" required defaultValue="Australia/Sydney">
                    {CLOCK_ZONES.map((zone) => <option key={zone} value={zone}>{zone}</option>)}
                  </select>
                </label>
                <button className={buttonCls} type="submit">Start the {CLOCK_RULES[kind].hours}-hour clock</button>
              </form>
            ) : <p className="text-sm text-muted">Not started.</p>}
          </article>
        );
      })}
      <p className="text-sm text-muted">{NOT_ADVICE}</p>
    </div>
  );
}
