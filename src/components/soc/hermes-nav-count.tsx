import type { AccessContext } from "@/lib/auth/access";
import { isHermesStaff } from "@/lib/services/hermes";
import { hermesRecentActionCount } from "@/lib/services/tuning";

/**
 * Hermes actions in the last 7 days, beside its navigation item. Streams in under Suspense so the shell never
 * waits on it; the count is cached for a minute (hermesRecentActionCount) and never breaks the navigation.
 */
export async function HermesNavCount({ ctx }: { ctx: AccessContext }) {
  if (!isHermesStaff(ctx)) return null;
  const n = await hermesRecentActionCount(ctx).catch(() => 0);
  if (!n) return null;
  const label = `${n} Hermes action${n === 1 ? "" : "s"} in the last 7 days`;
  return (
    <span title={label} className="num ml-auto rounded-full border border-hermes/35 bg-hermes/15 px-1.5 text-[10.5px] font-semibold leading-4 text-hermes">
      <span aria-hidden>{n > 99 ? "99+" : n}</span>
      <span className="sr-only">{label}</span>
    </span>
  );
}
