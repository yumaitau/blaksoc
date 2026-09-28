"use client";
import { useState, useTransition } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { ToggleSwitch } from "@/components/soc/toggle-switch";
import { Dialog, DialogClose, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import type { SectorTag } from "@/db/schema";
import { requestSightingAction, setFeedEnabledAction, setFeedEntitlementAction, tagIntelAction } from "./actions";

const label = (t: string) => t.replaceAll("_", " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());

/** Apply Australian sector relevance to an OpenCTI object (mirrored to OpenCTI labels). */
export function TagRelevance({ entity, current, allTags }: { entity: { id: string; entityType: string; name: string }; current: string[]; allTags: readonly SectorTag[] }) {
  const [open, setOpen] = useState(false);
  const [tags, setTags] = useState<string[]>(current);
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();
  const save = () =>
    start(async () => {
      setError(null);
      const r = await tagIntelAction({ openctiId: entity.id, entityType: entity.entityType, name: entity.name, tags: tags as SectorTag[] });
      if (r.ok) setOpen(false);
      else setError(r.error);
    });
  return (
    <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (o) setTags(current); }}>
      <DialogTrigger asChild>
        <Button variant="secondary" size="sm">Tag relevance</Button>
      </DialogTrigger>
      <DialogContent title="Tag relevance" description={`Sector relevance for ${entity.name}. Tags are mirrored to OpenCTI as labels.`}>
        <fieldset className="grid grid-cols-2 gap-2">
          <legend className="sr-only">Sector tags</legend>
          {allTags.map((t) => (
            <label key={t} className="flex items-center gap-2 text-sm">
              <Checkbox checked={tags.includes(t)} onCheckedChange={(c) => setTags((prev) => (c ? [...prev, t] : prev.filter((x) => x !== t)))} />
              {label(t)}
            </label>
          ))}
        </fieldset>
        {error ? <p role="alert" className="mt-3 text-sm text-danger">{error}</p> : null}
        <div className="mt-4 flex justify-end gap-2">
          <DialogClose asChild><Button variant="ghost" size="sm">Cancel</Button></DialogClose>
          <Button size="sm" onClick={save} disabled={pending}>{pending ? "Saving…" : "Save tags"}</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function ShareSightingButton({ matchId, disabled }: { matchId: string; disabled?: boolean }) {
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();
  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        variant="secondary"
        size="sm"
        disabled={disabled || pending}
        onClick={() =>
          start(async () => {
            setError(null);
            const r = await requestSightingAction(matchId);
            if (!r.ok) setError(r.error);
          })
        }
      >
        {pending ? "Queuing…" : "Share anonymised sighting"}
      </Button>
      {error ? <span role="alert" className="max-w-64 text-right text-xs text-danger">{error}</span> : null}
    </div>
  );
}

export function FeedToggle({ feedKey, name, enabled, canManage }: { feedKey: string; name: string; enabled: boolean; canManage: boolean }) {
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();
  return (
    <div className="flex items-center gap-2">
      <ToggleSwitch
        checked={enabled}
        disabled={!canManage || pending}
        label={`${name} enabled`}
        onChange={(v) =>
          start(async () => {
            setError(null);
            const r = await setFeedEnabledAction(feedKey, v);
            if (!r.ok) setError(r.error);
          })
        }
      />
      <span className="text-xs text-muted">{enabled ? "Enabled" : "Disabled"}</span>
      {error ? <span role="alert" className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}

export function EntitlementToggles({ feedKey, feedName, tenants, entitled, canManage }: { feedKey: string; feedName: string; tenants: { id: string; name: string }[]; entitled: string[]; canManage: boolean }) {
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap gap-x-4 gap-y-1.5">
        {tenants.map((t) => (
          <label key={t.id} className="flex items-center gap-1.5 text-xs">
            <Checkbox
              aria-label={`${t.name} entitled to ${feedName}`}
              checked={entitled.includes(t.id)}
              disabled={!canManage || pending}
              onCheckedChange={(c) =>
                start(async () => {
                  setError(null);
                  const r = await setFeedEntitlementAction(feedKey, t.id, c === true);
                  if (!r.ok) setError(r.error);
                })
              }
            />
            {t.name}
          </label>
        ))}
      </div>
      {error ? <p role="alert" className="text-xs text-danger">{error}</p> : null}
    </div>
  );
}
