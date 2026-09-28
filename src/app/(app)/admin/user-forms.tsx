"use client";
import { X } from "lucide-react";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Label, Select } from "@/components/ui/input";
import { assignRoleAction, revokeRoleAction, setUserDisabledAction } from "./actions";

export function RevokeButton({ assignmentId, label }: { assignmentId: string; label: string }) {
  const { pending, error, run } = useAction();
  return (
    <span className="inline-flex items-center">
      <button
        type="button"
        aria-label={`Revoke ${label}`}
        title={error ?? `Revoke ${label}`}
        disabled={pending}
        onClick={() => confirm(`Revoke ${label}?`) && run(() => revokeRoleAction(assignmentId))}
        className="ml-1 rounded text-faint hover:text-danger disabled:opacity-50"
      >
        <X className="size-3" />
      </button>
      {error ? <span role="alert" className="ml-1 text-[11px] text-danger">{error}</span> : null}
    </span>
  );
}

export function DisableButton({ userId, disabled, name }: { userId: string; disabled: boolean; name: string }) {
  const { pending, error, run } = useAction();
  return (
    <div className="text-right">
      <Button
        type="button"
        size="sm"
        variant={disabled ? "secondary" : "ghost"}
        disabled={pending}
        onClick={() => (disabled || confirm(`Disable ${name}? Their sessions stop working immediately.`)) && run(() => setUserDisabledAction(userId, !disabled))}
      >
        {disabled ? "Enable" : "Disable"}
      </Button>
      <ActionError error={error} />
    </div>
  );
}

export function AssignRoleForm({ users, roles, tenants }: { users: { id: string; label: string }[]; roles: { key: string; name: string; scope: "platform" | "tenant" }[]; tenants: { id: string; name: string }[] }) {
  const { pending, error, run } = useAction();
  const [userId, setUserId] = useState(users[0]?.id ?? "");
  const [roleKey, setRoleKey] = useState(roles[0]?.key ?? "");
  const [tenantId, setTenantId] = useState(tenants[0]?.id ?? "");
  const [ok, setOk] = useState(false);
  const role = roles.find((r) => r.key === roleKey);
  const needsTenant = role?.scope === "tenant";

  return (
    <form
      className="grid gap-3 sm:grid-cols-[1.4fr_1.2fr_1.2fr_auto] sm:items-end"
      onSubmit={(e) => {
        e.preventDefault();
        setOk(false);
        run(() => assignRoleAction({ userId, roleKey, tenantId: needsTenant ? tenantId : null }), () => setOk(true));
      }}
    >
      <div>
        <Label htmlFor="as-user">User</Label>
        <Select id="as-user" value={userId} onChange={(e) => setUserId(e.target.value)}>
          {users.map((u) => <option key={u.id} value={u.id}>{u.label}</option>)}
        </Select>
      </div>
      <div>
        <Label htmlFor="as-role">Role</Label>
        <Select id="as-role" value={roleKey} onChange={(e) => setRoleKey(e.target.value)}>
          {roles.map((r) => <option key={r.key} value={r.key}>{r.name} ({r.scope})</option>)}
        </Select>
      </div>
      <div>
        <Label htmlFor="as-tenant">Customer {needsTenant ? "" : "(platform roles span all customers)"}</Label>
        <Select id="as-tenant" value={tenantId} disabled={!needsTenant} onChange={(e) => setTenantId(e.target.value)}>
          {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </Select>
      </div>
      <Button type="submit" size="sm" disabled={pending || !userId || !roleKey}>{pending ? "Assigning…" : "Assign role"}</Button>
      <div className="sm:col-span-4">
        {ok ? <span role="status" className="text-sm text-ok">Role assigned. It applies from the user&apos;s next request.</span> : null}
        <ActionError error={error} />
      </div>
    </form>
  );
}
