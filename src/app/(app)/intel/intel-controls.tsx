"use client";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
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
  const { pending, error, run } = useAction();
  const save = () =>
    run(() => tagIntelAction({ openctiId: entity.id, entityType: entity.entityType, name: entity.name, tags: tags as SectorTag[] }), () => setOpen(false), {
      success: `Relevance tags saved for ${entity.name}`,
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
        <div className="mt-3 empty:hidden"><ActionError error={error} /></div>
        <div className="mt-4 flex justify-end gap-2">
          <DialogClose asChild><Button variant="ghost" size="sm">Cancel</Button></DialogClose>
          <Button size="sm" onClick={save} disabled={pending}>{pending ? "Saving…" : "Save tags"}</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function ShareSightingButton({ matchId, disabled }: { matchId: string; disabled?: boolean }) {
  const { pending, error, run } = useAction();
  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        variant="secondary"
        size="sm"
        disabled={disabled || pending}
        onClick={() => run(() => requestSightingAction(matchId), undefined, { success: "Anonymised sighting queued for sharing" })}
      >
        {pending ? "Queuing…" : "Share anonymised sighting"}
      </Button>
      {error ? <span role="alert" className="max-w-64 text-right text-xs text-danger">{error}</span> : null}
    </div>
  );
}

export function FeedToggle({ feedKey, name, enabled, canManage }: { feedKey: string; name: string; enabled: boolean; canManage: boolean }) {
  const { pending, error, run } = useAction();
  return (
    <div className="flex items-center gap-2">
      <ToggleSwitch
        checked={enabled}
        disabled={!canManage || pending}
        label={`${name} enabled`}
        onChange={(v) => run(() => setFeedEnabledAction(feedKey, v), undefined, { success: `${name} feed ${v ? "enabled" : "disabled"}` })}
      />
      <span className="text-xs text-muted">{enabled ? "Enabled" : "Disabled"}</span>
      {error ? <span role="alert" className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}

export function EntitlementToggles({ feedKey, feedName, tenants, entitled, canManage }: { feedKey: string; feedName: string; tenants: { id: string; name: string }[]; entitled: string[]; canManage: boolean }) {
  const { pending, error, run } = useAction();
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
                run(() => setFeedEntitlementAction(feedKey, t.id, c === true), undefined, {
                  success: c === true ? `${t.name} now receives ${feedName}` : `${t.name} no longer receives ${feedName}`,
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
