"use client";
import { useState, useTransition } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input, Label, Select } from "@/components/ui/input";
import { EXPOSURES } from "../asset-bits";
import { saveAssetContext } from "./actions";

export function EditAsset({ id, criticality, exposure, owner, privileged, isIdentity }: { id: string; criticality: number; exposure: string; owner: string | null; privileged: boolean; isIdentity: boolean }) {
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [priv, setPriv] = useState(privileged);

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        start(async () => {
          const r = await saveAssetContext(id, {
            criticality: Number(f.get("criticality")),
            exposure: String(f.get("exposure")),
            owner: String(f.get("owner") ?? ""),
            ...(isIdentity ? { privileged: priv } : {}),
          });
          setMsg(r.ok ? { ok: true, text: "Saved." } : { ok: false, text: r.error });
        });
      }}
    >
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label htmlFor="criticality">Criticality</Label>
          <Select id="criticality" name="criticality" defaultValue={String(criticality)}>
            <option value="1">1 · low</option>
            <option value="2">2</option>
            <option value="3">3 · standard</option>
            <option value="4">4 · critical</option>
            <option value="5">5 · crown jewel</option>
          </Select>
        </div>
        <div>
          <Label htmlFor="exposure">Exposure</Label>
          <Select id="exposure" name="exposure" defaultValue={exposure}>
            {EXPOSURES.map((x) => <option key={x} value={x}>{x}</option>)}
          </Select>
        </div>
      </div>
      <div>
        <Label htmlFor="owner">Owner</Label>
        <Input id="owner" name="owner" defaultValue={owner ?? ""} placeholder="Team or person responsible" maxLength={200} />
      </div>
      {isIdentity ? (
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={priv} onCheckedChange={(v) => setPriv(v === true)} aria-label="Privileged identity" />
          Privileged identity (admin or service account)
        </label>
      ) : null}
      <div className="flex items-center gap-3">
        <Button type="submit" size="sm" disabled={pending}>{pending ? "Saving…" : "Save context"}</Button>
        {msg ? <span role="status" className={msg.ok ? "text-xs text-ok" : "text-xs text-danger"}>{msg.text}</span> : null}
      </div>
    </form>
  );
}
