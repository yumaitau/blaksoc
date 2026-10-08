"use client";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input, Label, Select } from "@/components/ui/input";
import { createRoleAction } from "./actions";

export function CreateRoleForm({ permissions }: { permissions: readonly string[] }) {
  const { pending, error, run } = useAction();
  const [key, setKey] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scope, setScope] = useState<"platform" | "tenant">("tenant");
  const [picked, setPicked] = useState<string[]>([]);
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => createRoleAction({ key, name, scope, permissions: picked, description }), () => {
          setKey("");
          setName("");
          setDescription("");
          setPicked([]);
        }, { success: `Role ${name.trim()} created` });
      }}
    >
      <div className="grid gap-3 sm:grid-cols-4">
        <div>
          <Label htmlFor="r-key">Key (stored as custom_…)</Label>
          <Input id="r-key" value={key} required pattern="[a-z0-9_]{2,40}" onChange={(e) => setKey(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="r-name">Name</Label>
          <Input id="r-name" value={name} required onChange={(e) => setName(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="r-scope">Scope</Label>
          <Select id="r-scope" value={scope} onChange={(e) => setScope(e.target.value as "platform" | "tenant")}>
            <option value="tenant">Tenant (one customer)</option>
            <option value="platform">Platform (all customers)</option>
          </Select>
        </div>
        <div>
          <Label htmlFor="r-desc">Description</Label>
          <Input id="r-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
      </div>
      <fieldset>
        <legend className="mb-1 text-xs font-medium text-muted">Permissions ({picked.length} selected)</legend>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 sm:grid-cols-3 lg:grid-cols-5">
          {permissions.map((p) => (
            <label key={p} className="flex items-center gap-1.5 font-mono text-[11.5px]">
              <Checkbox checked={picked.includes(p)} onCheckedChange={(v) => setPicked((x) => (v === true ? [...x, p] : x.filter((y) => y !== p)))} />
              {p}
            </label>
          ))}
        </div>
      </fieldset>
      <div className="flex items-center gap-3">
        <Button type="submit" size="sm" disabled={pending}>{pending ? "Creating…" : "Create role"}</Button>
        <ActionError error={error} />
      </div>
    </form>
  );
}
