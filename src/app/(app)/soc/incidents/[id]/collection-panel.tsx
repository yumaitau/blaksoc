"use client";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input, Label } from "@/components/ui/input";
import { ARTIFACT_LABELS, ARTIFACT_SETS, type ArtifactSet } from "@/lib/dfir/sets";
import { exportIncidentCustody, requestIncidentCollection, startIncidentHunt } from "../actions";

const matched = (n: number) => (n === 1 ? "1 machine matched." : `${n} machines matched.`);

export function CollectionPanel({
  incidentId,
  editable,
  targets,
  collections,
}: {
  incidentId: string;
  editable: boolean;
  targets: { id: string; label: string }[];
  collections: { id: string; label: string; detail: string; when: string }[];
}) {
  const [assetIds, setAssetIds] = useState<string[]>([]);
  const [sets, setSets] = useState<ArtifactSet[]>(["triage"]);
  const [lowBandwidth, setLowBandwidth] = useState(false);
  const [ioc, setIoc] = useState("");
  const collect = useAction();
  const hunt = useAction();
  const custody = useAction();

  function toggleAsset(id: string, on: boolean) {
    setAssetIds((prev) => (on ? [...prev, id] : prev.filter((x) => x !== id)));
  }
  function toggleSet(set: ArtifactSet, on: boolean) {
    setSets((prev) => (on ? [...prev, set] : prev.filter((x) => x !== set)));
  }

  return (
    <div className="space-y-4">
      {collections.length === 0 ? <p className="text-sm text-muted">No collections yet.</p> : (
        <ul className="space-y-2">
          {collections.map((row) => (
            <li key={row.id} className="rounded-md border border-border px-3 py-2">
              <div className="text-sm font-medium">{row.label}</div>
              <div className="text-xs text-muted">{row.detail} · {row.when}</div>
            </li>
          ))}
        </ul>
      )}
      {editable ? (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            collect.run(() => requestIncidentCollection(incidentId, { assetIds, artifactSets: sets, lowBandwidth }), undefined, {
              success: `Collection requested from ${assetIds.length} machine${assetIds.length === 1 ? "" : "s"}. It waits for approval.`,
            });
          }}
        >
          <p className="text-sm text-muted">Pick the machines and the artifact sets. Every set waits for approval before anything is collected.</p>
          {targets.length === 0 ? <p className="text-sm text-muted">No endpoint assets for this customer yet.</p> : (
            <ul className="grid max-h-48 gap-2 overflow-y-auto sm:grid-cols-2">
              {targets.map((target) => (
                <li key={target.id}>
                  <label className="flex items-center gap-2 text-sm">
                    <Checkbox checked={assetIds.includes(target.id)} onCheckedChange={(v) => toggleAsset(target.id, v === true)} aria-label={target.label} />
                    <span className="truncate">{target.label}</span>
                  </label>
                </li>
              ))}
            </ul>
          )}
          <div className="flex flex-wrap gap-3">
            {ARTIFACT_SETS.map((set) => (
              <label key={set} className="flex items-center gap-2 text-sm">
                <Checkbox checked={sets.includes(set)} onCheckedChange={(v) => toggleSet(set, v === true)} aria-label={ARTIFACT_LABELS[set]} />
                <span>{ARTIFACT_LABELS[set]}</span>
              </label>
            ))}
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={lowBandwidth} onCheckedChange={(v) => setLowBandwidth(v === true)} aria-label="Low bandwidth" />
            <span>Low bandwidth. At most 3 machines. The upload waits 15 minutes.</span>
          </label>
          <ActionError error={collect.error} />
          <Button type="submit" disabled={collect.pending || assetIds.length === 0 || sets.length === 0}>Request collection</Button>
        </form>
      ) : null}
      {editable ? (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            hunt.run(() => startIncidentHunt(incidentId, ioc), () => setIoc(""), { success: (data) => `Hunt finished: ${matched(data?.matches ?? 0)}` });
          }}
        >
          <div className="min-w-0 flex-1">
            <Label htmlFor={`${incidentId}-ioc`}>Indicator from threat intel</Label>
            <Input id={`${incidentId}-ioc`} value={ioc} onChange={(e) => setIoc(e.target.value)} placeholder="Domain, hash, or address" />
          </div>
          <Button type="submit" variant="secondary" disabled={hunt.pending || !ioc.trim()}>Hunt this customer&apos;s machines</Button>
          <ActionError error={hunt.error} />
        </form>
      ) : null}
      <div>
        <Button
          type="button"
          variant="outline"
          disabled={custody.pending}
          onClick={() => custody.run(async () => {
            const res = await exportIncidentCustody(incidentId);
            if (res.ok && res.data?.text) {
              const blob = new Blob([res.data.text], { type: "text/plain" });
              const url = URL.createObjectURL(blob);
              const link = document.createElement("a");
              link.href = url;
              link.download = "chain-of-custody.txt";
              link.click();
              URL.revokeObjectURL(url);
            }
            return res;
          }, undefined, { success: "Chain of custody downloaded" })}
        >
          Download chain of custody
        </Button>
        <ActionError error={custody.error} />
      </div>
    </div>
  );
}
