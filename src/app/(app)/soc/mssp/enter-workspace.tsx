"use client";
import { LogIn } from "lucide-react";
import { useRouter } from "next/navigation";
import { setWorkspace } from "@/app/(app)/workspace-actions";
import { useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";

export function EnterWorkspace({ tenantId, name }: { tenantId: string; name: string }) {
  const router = useRouter();
  const { pending, run } = useAction();
  return (
    <Button
      size="sm"
      variant="secondary"
      disabled={pending}
      aria-label={`Enter ${name} workspace`}
      onClick={() => run(() => setWorkspace(tenantId), () => router.push("/soc"), { success: (id) => (id === tenantId ? `Now viewing ${name}` : "Now viewing all customers") })}
    >
      <LogIn />
      {pending ? "Entering…" : "Enter workspace"}
    </Button>
  );
}
