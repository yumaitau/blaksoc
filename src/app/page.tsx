import { redirect } from "next/navigation";
import { requireAccess } from "@/lib/auth/session";

export default async function Home() {
  const ctx = await requireAccess();
  if (!ctx.grants.length) redirect("/access-pending");
  redirect(ctx.isPlatform ? "/soc" : "/portal");
}
