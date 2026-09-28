"use client";
import { LogIn } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { setWorkspace } from "@/app/(app)/workspace-actions";
import { Button } from "@/components/ui/button";

export function EnterWorkspace({ tenantId, name }: { tenantId: string; name: string }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  return (
    <Button
      size="sm"
      variant="secondary"
      disabled={pending}
      aria-label={`Enter ${name} workspace`}
      onClick={() =>
        start(async () => {
          await setWorkspace(tenantId);
          router.push("/soc");
        })
      }
    >
      <LogIn />
      {pending ? "Entering…" : "Enter workspace"}
    </Button>
  );
}
