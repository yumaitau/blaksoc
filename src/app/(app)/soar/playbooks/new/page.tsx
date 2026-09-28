import Link from "next/link";
import { redirect } from "next/navigation";
import { PageHeader } from "@/components/soc/indicators";
import { requireAccess } from "@/lib/auth/session";
import { stepCatalogue } from "@/lib/soar/engine";
import { playbookOwners } from "@/lib/services/playbooks";
import { PlaybookEditor } from "../playbook-editor";

export const metadata = { title: "New playbook" };

export default async function NewPlaybookPage() {
  const ctx = await requireAccess();
  const owners = playbookOwners(ctx);
  if (!owners.length) redirect("/soar/playbooks");
  return (
    <div>
      <PageHeader
        eyebrow="Playbooks"
        title="New playbook"
        description="New playbooks are created disabled. Review the flow, then enable it from the playbook list."
        actions={<Link href="/soar/playbooks" className="text-sm text-accent hover:underline">← All playbooks</Link>}
      />
      <PlaybookEditor
        canEdit
        owners={owners}
        catalogue={stepCatalogue()}
        initial={{
          tenantId: owners[0]!.id,
          name: "",
          description: "",
          trigger: { event: "alert.created", conditions: [{ field: "alert.riskScore", op: "gte", value: 70 }] },
          steps: [
            { id: "enrich", action: "intel.enrich", name: "Query OpenCTI" },
            { id: "asset", action: "asset.context", name: "Check asset importance" },
            { id: "notify", action: "notify", name: "Notify analyst" },
          ],
        }}
      />
    </div>
  );
}
