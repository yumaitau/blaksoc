import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import type { Hit, Relevance } from "@/lib/intel/relevance";

const n = (h: Hit) => (h.assets ? ` · ${h.assets} asset${h.assets === 1 ? "" : "s"}` : h.alerts ? ` · ${h.alerts} alert${h.alerts === 1 ? "" : "s"}` : "");

/** Why an advisory touches the estate: open CVEs, installed software, operating systems, techniques seen in alerts. */
export function RelevanceLine({ r, compact = false }: { r: Relevance; compact?: boolean }) {
  if (!r.score) return null;
  const limit = compact ? 2 : 5;
  return (
    <div className="mt-1.5 flex flex-wrap items-center gap-1.5" aria-label="Why this is relevant">
      <span className="text-[11px] font-medium text-warn">Relevant</span>
      {r.cves.slice(0, limit).map((h) => (
        <Link key={h.label} href={`/vulnerabilities?cve=${h.label}`}><Badge variant="danger" className="font-mono" title="Open on assets in this estate">{h.label}{n(h)}</Badge></Link>
      ))}
      {r.software.slice(0, limit).map((h) => (
        <Badge key={h.label} variant="warn" title="Installed software named in the advisory">{h.label}{n(h)}</Badge>
      ))}
      {r.os.slice(0, limit).map((h) => (
        <Badge key={h.label} variant="outline" title="Operating system named in the advisory">{h.label}{n(h)}</Badge>
      ))}
      {r.techniques.slice(0, limit).map((h) => (
        <Link key={h.label} href={`/detections/attack?t=${h.label}`}>
          <Badge variant="intel" title="Seen in this estate's alerts in the last 30 days; tuned-out noise and false positives excluded">{h.label} seen{n(h)}</Badge>
        </Link>
      ))}
    </div>
  );
}
