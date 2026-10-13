import { LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";

export function SignOutButton({ compact }: { compact?: boolean }) {
  return (
    <form action="/api/auth/logout" method="post">
      <Button type="submit" variant="ghost" size={compact ? "icon" : "default"} aria-label="Sign out">
        <LogOut />
        {compact ? null : "Sign out"}
      </Button>
    </form>
  );
}
