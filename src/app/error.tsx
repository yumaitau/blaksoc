"use client";
import { type BoundaryError, ErrorPanel } from "@/components/soc/error-panel";

/** Sign-in, account and onboarding pages; the SOC and portal groups have their own boundaries. */
export default function RootError({ error, retry }: { error: BoundaryError; retry: () => void }) {
  return <div className="px-4"><ErrorPanel error={error} retry={retry} /></div>;
}
