import { randomUUID } from "node:crypto";
import Link from "next/link";
import { redirect } from "next/navigation";
import { PageHeader } from "@/components/soc/indicators";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { RuleEditor } from "../rule-controls";

export const metadata = { title: "New detection rule" };

const template = (id: string) => `title: New detection
id: ${id}
status: experimental
description: What this detects and why it matters.
author: Yuma IT blakSOC
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\example.exe'
  condition: selection
falsepositives:
  - Document known benign sources here
level: medium
tags:
  - attack.execution
  - attack.t1059
`;

export default async function NewRulePage() {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal");
  const scopes = [
    ...(can(ctx, "detection:write") ? [{ value: "global", label: "Global (platform)" }] : []),
    ...ctx.tenants.filter((t) => t.kind === "customer" && can(ctx, "detection:write", t.id)).map((t) => ({ value: t.id, label: t.name })),
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Detect"
        title="New detection rule"
        description="Write a Sigma rule. It is validated on save and stored as version 1; test it before deploying to customers."
        actions={<Link href="/detections" className="text-sm text-accent hover:underline">← All rules</Link>}
      />
      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader><CardTitle>Rule</CardTitle></CardHeader>
          <CardContent>
            <RuleEditor initialYaml={template(randomUUID())} initialConfidence={50} scopes={scopes} canWrite={scopes.length > 0} />
          </CardContent>
        </Card>
        <Card className="self-start">
          <CardHeader><CardTitle>Authoring notes</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm text-muted">
            <p><span className="text-fg">Global</span> rules are maintained by the SOC and can be deployed to any customer. <span className="text-fg">Customer</span> rules are visible to and deployable on that customer only.</p>
            <p>Tag ATT&CK techniques as <code className="font-mono text-xs text-fg">attack.t1059.001</code>; they drive the coverage matrix.</p>
            <p>Document false positives under <code className="font-mono text-xs text-fg">falsepositives</code> so triage analysts know what benign looks like.</p>
            <p>Supported: field maps, value lists, keywords, the contains / startswith / endswith / re / all / exists modifiers, and full conditions including “1 of” and “all of”.</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
