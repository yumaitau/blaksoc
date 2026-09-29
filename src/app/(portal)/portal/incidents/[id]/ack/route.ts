import { redirect } from "next/navigation";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { acknowledgeIncident } from "@/lib/services/incidents";

export async function POST(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const access = await currentAccess();
  if (!access) redirect("/login");
  try {
    await acknowledgeIncident(access, id);
  } catch (err) {
    if (err instanceof AccessDenied) return new Response("Not found", { status: 404 });
    throw err;
  }
  redirect(`/portal/incidents/${id}`);
}
