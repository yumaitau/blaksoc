"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ToggleSwitch } from "@/components/soc/toggle-switch";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { deployRuleAction, saveRuleAction, setRuleEnabledAction, testRuleAction } from "./actions";

export function RuleEnabledToggle({ id, title, enabled, canWrite }: { id: string; title: string; enabled: boolean; canWrite: boolean }) {
  const { pending, error, run } = useAction();
  return (
    <span className="inline-flex items-center gap-2" title={error ?? undefined}>
      <ToggleSwitch checked={enabled} disabled={!canWrite || pending} label={`${title} enabled`} onChange={(v) => run(() => setRuleEnabledAction(id, v))} />
      {error ? <span role="alert" className="text-xs text-danger">{error}</span> : null}
    </span>
  );
}

/** YAML workspace. Every save is a new immutable version with a change note. */
export function RuleEditor({
  ruleId,
  initialYaml,
  initialConfidence,
  scopes,
  canWrite,
}: {
  ruleId?: string;
  initialYaml: string;
  initialConfidence: number;
  /** Tenant scope choices for a new rule; omitted when editing (scope is fixed). */
  scopes?: { value: string; label: string }[];
  canWrite: boolean;
}) {
  const router = useRouter();
  const [yaml, setYaml] = useState(initialYaml);
  const [note, setNote] = useState(ruleId ? "" : "Initial version");
  const [confidence, setConfidence] = useState(String(initialConfidence));
  const [scope, setScope] = useState(scopes?.[0]?.value ?? "global");
  const [saved, setSaved] = useState<string | null>(null);
  const { pending, error, run } = useAction();
  const dirty = yaml !== initialYaml || Number(confidence) !== initialConfidence;

  const save = () => {
    setSaved(null);
    run(
      () => saveRuleAction({ id: ruleId, tenantId: scope === "global" ? null : scope, yaml, changeNote: note, confidence: confidence === "" ? undefined : Number(confidence) }),
      (data) => {
        if (!data) return;
        if (!ruleId) router.push(`/detections/rules/${data.id}`);
        else {
          setSaved(`Saved as version ${data.version}.`);
          setNote("");
          router.refresh();
        }
      },
    );
  };

  return (
    <div className="space-y-3">
      {scopes ? (
        <div className="max-w-sm">
          <Label htmlFor="rule-scope">Tenant scope</Label>
          <Select id="rule-scope" value={scope} onChange={(e) => setScope(e.target.value)} disabled={!canWrite}>
            {scopes.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </Select>
        </div>
      ) : null}
      <div>
        <Label htmlFor="rule-yaml">Sigma rule (YAML)</Label>
        <Textarea
          id="rule-yaml"
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
          spellCheck={false}
          readOnly={!canWrite}
          className="min-h-[420px] font-mono text-[12.5px] leading-5"
          aria-describedby={error ? "rule-yaml-error" : undefined}
        />
      </div>
      <div className="grid gap-3 sm:grid-cols-[1fr_140px]">
        <div>
          <Label htmlFor="rule-note">Change note</Label>
          <Input id="rule-note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="What changed and why" disabled={!canWrite} />
        </div>
        <div>
          <Label htmlFor="rule-confidence">Confidence (0–100)</Label>
          <Input id="rule-confidence" type="number" min={0} max={100} value={confidence} onChange={(e) => setConfidence(e.target.value)} disabled={!canWrite} />
        </div>
      </div>
      <div id="rule-yaml-error"><ActionError error={error} /></div>
      {saved ? <p role="status" className="text-sm text-ok">{saved}</p> : null}
      <div className="flex items-center gap-3">
        <Button onClick={save} disabled={!canWrite || pending || (!!ruleId && !dirty) || !note.trim()}>
          {pending ? "Saving…" : ruleId ? "Save new version" : "Create rule"}
        </Button>
        {!canWrite ? <span className="text-xs text-muted">Read only: detection:write is required.</span> : !note.trim() ? <span className="text-xs text-muted">A change note is required.</span> : null}
      </div>
    </div>
  );
}

type TestResult = { name: string; matched: boolean; pass: boolean };

export function TestRunner({ ruleId, example, canRun }: { ruleId: string; example: string; canRun: boolean }) {
  const [cases, setCases] = useState(example);
  const [result, setResult] = useState<{ results: TestResult[]; passed: boolean } | null>(null);
  const { pending, error, run } = useAction();
  return (
    <div className="space-y-3">
      <div>
        <Label htmlFor="rule-tests">Test cases (JSON array of {"{ name, event, expect }"})</Label>
        <Textarea id="rule-tests" value={cases} onChange={(e) => setCases(e.target.value)} spellCheck={false} className="min-h-48 font-mono text-[12px] leading-5" disabled={!canRun} />
      </div>
      <ActionError error={error} />
      <div className="flex items-center gap-3">
        <Button variant="secondary" disabled={!canRun || pending} onClick={() => run(() => testRuleAction(ruleId, cases), (d) => setResult(d ?? null))}>
          {pending ? "Running…" : "Run tests against current version"}
        </Button>
        {result ? <Badge variant={result.passed ? "ok" : "danger"}>{result.passed ? "All passed" : "Failures"}</Badge> : null}
      </div>
      {result ? <TestResultsTable results={result.results} /> : null}
    </div>
  );
}

export function TestResultsTable({ results }: { results: TestResult[] }) {
  return (
    <Table>
      <THead>
        <TR><TH>Case</TH><TH>Matched</TH><TH>Result</TH></TR>
      </THead>
      <TBody>
        {results.map((r, i) => (
          <TR key={`${r.name}-${i}`}>
            <TD className="text-sm">{r.name}</TD>
            <TD className="text-xs text-muted">{r.matched ? "Yes" : "No"}</TD>
            <TD><Badge variant={r.pass ? "ok" : "danger"}>{r.pass ? "Pass" : "Fail"}</Badge></TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}

export function DeployPanel({ ruleId, customers, canDeploy, enabled }: { ruleId: string; customers: { id: string; name: string; deployedVersion: number | null }[]; canDeploy: boolean; enabled: boolean }) {
  const [selected, setSelected] = useState<string[]>([]);
  const [out, setOut] = useState<{ query: string; deployed: number } | null>(null);
  const { pending, error, run } = useAction();
  const toggle = (id: string, on: boolean) => setSelected((s) => (on ? [...s, id] : s.filter((x) => x !== id)));
  if (!customers.length) return <p className="text-sm text-muted">No customers in scope for deployment.</p>;
  return (
    <div className="space-y-3">
      <fieldset>
        <legend className="mb-1.5 text-xs font-medium text-muted">Deploy the current version to</legend>
        <div className="grid gap-1.5 sm:grid-cols-2">
          {customers.map((c) => (
            <label key={c.id} className="flex items-center gap-2 text-sm">
              <Checkbox checked={selected.includes(c.id)} onCheckedChange={(v) => toggle(c.id, v === true)} disabled={!canDeploy || pending} />
              <span className="truncate">{c.name}</span>
              {c.deployedVersion != null ? <span className="text-[11px] text-faint">v{c.deployedVersion} deployed</span> : null}
            </label>
          ))}
        </div>
      </fieldset>
      <ActionError error={error} />
      <div className="flex flex-wrap items-center gap-3">
        <Button disabled={!canDeploy || !enabled || pending || !selected.length} onClick={() => run(() => deployRuleAction(ruleId, selected), (d) => { setOut(d ?? null); setSelected([]); })}>
          {pending ? "Deploying…" : `Deploy to ${selected.length || "selected"} customer${selected.length === 1 ? "" : "s"}`}
        </Button>
        {!canDeploy ? <span className="text-xs text-muted">detection:deploy is required.</span> : !enabled ? <span className="text-xs text-muted">Enable the rule before deploying.</span> : null}
      </div>
      {out ? (
        <div role="status" className="space-y-1.5">
          <p className="text-sm text-ok">Deployed to {out.deployed} customer{out.deployed === 1 ? "" : "s"}. Generated Wazuh-indexer (OpenSearch) query:</p>
          <pre className="overflow-x-auto rounded-md border border-border bg-bg p-3 font-mono text-[12px] text-fg">{out.query}</pre>
        </div>
      ) : null}
    </div>
  );
}
