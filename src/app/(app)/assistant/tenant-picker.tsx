"use client";
import { useRouter } from "next/navigation";
import { Label, Select } from "@/components/ui/input";

export function TenantPicker({ tenants, value }: { tenants: { id: string; name: string }[]; value: string }) {
  const router = useRouter();
  return (
    <div className="w-60">
      <Label htmlFor="assistant-tenant">Customer</Label>
      <Select id="assistant-tenant" value={value} onChange={(e) => router.push(`/assistant?tenant=${e.target.value}`)}>
        {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
      </Select>
    </div>
  );
}
