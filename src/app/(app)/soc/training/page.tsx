import { redirect } from "next/navigation";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { mentorBoard } from "@/lib/services/training";
import { listScenarios } from "@/lib/training/scenarios";
import { cosign } from "./actions";

export const metadata = { title: "Training" };

/** Mentor view of replayable demo scenarios. Training rooms are not customer queues. */
export default async function TrainingPage() {
  const ctx = await requireAccess();
  if (!ctx.isPlatform || !can(ctx, "alert:assign")) redirect("/soc");
  const board = await mentorBoard(ctx);
  const scenarios = listScenarios();

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Operate"
        title="Training"
        description="Replayable scenarios on the demo provider. Mentors see scores. This is not a customer queue."
      />
      {board.length === 0 ? (
        <EmptyState title="No training rooms">Open a training tenant before a trainee starts a scenario.</EmptyState>
      ) : (
        board.map((room) => (
          <section key={room.id} className="space-y-3">
            <h2 className="text-sm font-medium">{room.name}</h2>
            {room.trainees.length === 0 ? (
              <EmptyState title="No trainees">No one has started a scenario in this room.</EmptyState>
            ) : (
              <ul className="grid gap-3">
                {room.trainees.map((trainee) => {
                  const passed = trainee.skills.filter((skill) => skill.passed).map((skill) => skill.skill);
                  return (
                    <li key={trainee.traineeId} className="min-w-0 rounded-lg border border-border bg-surface p-3">
                      <div className="font-medium">{trainee.traineeName}</div>
                      <div className="mt-2 grid grid-cols-2 gap-2 text-sm">
                        <div className="text-muted">Attempts <span className="num text-fg">{trainee.attempts}</span></div>
                        <div className="text-muted">Average <span className="num text-fg">{trainee.averageScore}</span></div>
                        <div className="col-span-2 min-w-0 text-muted">Skills <span className="text-fg">{passed.length ? passed.join(", ") : "None passed"}</span></div>
                        <div className="col-span-2 text-muted">
                          Shadowing{" "}
                          {trainee.cosigned ? (
                            <span className="text-fg">Co-signed</span>
                          ) : (
                            <form action={cosign} className="mt-2">
                              <input type="hidden" name="tenantId" value={room.id} />
                              <input type="hidden" name="traineeId" value={trainee.traineeId} />
                              <button className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 font-medium text-accent-fg" type="submit">
                                Co-sign
                              </button>
                            </form>
                          )}
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>
        ))
      )}
      <section className="grid gap-3 sm:grid-cols-2">
        {scenarios.map((scenario) => (
          <article key={scenario.id} className="min-w-0 rounded-lg border border-border bg-surface p-3">
            <h2 className="font-medium">{scenario.title}</h2>
            <p className="mt-1 text-sm text-muted">{scenario.tags.join(", ")}</p>
          </article>
        ))}
      </section>
    </div>
  );
}
