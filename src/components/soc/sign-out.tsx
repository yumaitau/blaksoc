"use client";
import { LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { authClient } from "@/lib/auth/client";

export function SignOutButton({ compact }: { compact?: boolean }) {
  return (
    <Button variant="ghost" size={compact ? "icon" : "default"} aria-label="Sign out" onClick={async () => { await authClient.signOut(); window.location.href = "/login"; }}>
      <LogOut />
      {compact ? null : "Sign out"}
    </Button>
  );
}
