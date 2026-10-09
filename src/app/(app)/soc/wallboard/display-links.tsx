"use client";

import { useEffect, useState, useTransition } from "react";
import { Button } from "@/components/ui/button";
import { Input, Label, Select } from "@/components/ui/input";
import { displayLinkRows, type DisplayLink } from "@/lib/wallboard/display-links";
import { WALLBOARD_EXPIRY_DAYS, type WallboardExpiryDays } from "@/lib/wallboard/types";
import { createWallboardLinkAction, revokeWallboardLinkAction } from "./actions";
import styles from "./display-links.module.css";

const formattedDate = (value: string) => new Date(value).toLocaleString("en-AU", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });

export function DisplayLinks({ customers, initialLinks, initialNow }: { customers: { id: string; name: string }[]; initialLinks: DisplayLink[]; initialNow: number }) {
  const [name, setName] = useState("");
  const [picked, setPicked] = useState<string[]>(customers.map((customer) => customer.id));
  const [days, setDays] = useState<WallboardExpiryDays>(30);
  const [issued, setIssued] = useState<{ url: string; expiresAt: string } | null>(null);
  const [createdLinks, setCreatedLinks] = useState<DisplayLink[]>([]);
  const [revokedLinks, setRevokedLinks] = useState<Record<string, string>>({});
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const [now, setNow] = useState(initialNow);
  const links = displayLinkRows(initialLinks, createdLinks, revokedLinks);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  return <section className="space-y-5" aria-labelledby="display-links-heading">
    <div><h2 id="display-links-heading" className="text-lg font-semibold">Signed display links</h2><p className="mt-1 max-w-3xl text-sm text-muted">Anyone with a link can view its customer summaries without signing in. Links show counts and case references; alert details, raw events and analyst names stay private. Keep the link on trusted office displays.</p></div>
    <form className="space-y-4 rounded-lg border border-border p-5" onSubmit={(event) => {
      event.preventDefault();
      setError(null); setIssued(null); setCopied(false); setCopyError(false);
      startTransition(async () => {
        try {
          const result = await createWallboardLinkAction({ name, tenantIds: picked, expiresInDays: days });
          if (!result.ok) { setError(result.error); return; }
          if (!result.data) return;
          setIssued(result.data);
          setCreatedLinks((previous) => [{ id: result.data!.id, expiresAt: result.data!.expiresAt, name: name.trim(), tenantIds: picked, createdBy: "", createdAt: new Date().toISOString(), revokedAt: null }, ...previous]);
          setName("");
        } catch { setError("The link could not be created. Check your connection and try again."); }
      });
    }}>
      <div className="grid gap-4 sm:grid-cols-2"><div><Label htmlFor="display-name">Display name</Label><Input id="display-name" className={styles.field} required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="Office TV" /></div><div><Label htmlFor="display-expiry">Link lifetime</Label><Select id="display-expiry" className={styles.field} value={days} onChange={(event) => setDays(Number(event.target.value) as WallboardExpiryDays)}>{WALLBOARD_EXPIRY_DAYS.map((value) => <option key={value} value={value}>{value} day{value === 1 ? "" : "s"}</option>)}</Select></div></div>
      <fieldset><legend className="mb-2 text-sm font-medium">Customers on this display</legend><p className="mb-3 text-xs text-muted">The customer list is fixed when the link is created. New customers need a new link.</p><div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{customers.map((customer) => <label key={customer.id} className="flex min-h-8 cursor-pointer items-center gap-2 text-sm"><input type="checkbox" className="size-4 accent-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent" checked={picked.includes(customer.id)} onChange={(event) => setPicked((previous) => event.target.checked ? [...previous, customer.id] : previous.filter((id) => id !== customer.id))} />{customer.name}</label>)}</div>{!customers.length ? <p className="text-sm text-muted">Select a workspace with operational customers to create a link.</p> : null}</fieldset>
      <Button type="submit" disabled={pending || !name.trim() || !picked.length}>{pending ? "Saving…" : "Generate signed link"}</Button>
      {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
      {issued ? <div className="space-y-3 rounded-md bg-surface-2 p-4"><p role="status" className="text-sm font-medium">Display link created · expires {formattedDate(issued.expiresAt)}</p><Label htmlFor="issued-link">Copy this link now. It is only shown here.</Label><Input id="issued-link" className={styles.field} readOnly value={issued.url} onFocus={(event) => event.target.select()} /><div className="flex flex-wrap items-center gap-3"><Button type="button" variant="secondary" onClick={async () => {
        try { await navigator.clipboard.writeText(issued.url); setCopied(true); setCopyError(false); } catch { setCopyError(true); }
      }}>{copied ? "Copied" : "Copy link"}</Button><a href={issued.url} target="_blank" rel="noopener noreferrer" className="text-sm text-fg underline underline-offset-4 focus-visible:outline-2 focus-visible:outline-accent">Open signed display</a></div>{copyError ? <p role="status" className="text-sm text-warn">Select the link above and copy it manually.</p> : null}</div> : null}
    </form>
    <div><h3 className="mb-3 font-medium">Recent display links</h3><p className="mb-3 text-xs text-muted">Revoking a link stops its next refresh. Active TVs check access every 30 seconds.</p>{links.length ? <ul className="divide-y divide-border rounded-lg border border-border">{links.map((link) => {
      const inactive = !!link.revokedAt || Date.parse(link.expiresAt) <= now;
      return <li key={link.id} className="flex flex-wrap items-center justify-between gap-3 p-4"><div className="min-w-0"><p className="break-words text-sm font-medium">{link.name}</p><p className="mt-1 text-xs text-muted">{link.tenantIds.length} customer{link.tenantIds.length === 1 ? "" : "s"} · {link.revokedAt ? "Revoked" : inactive ? "Expired" : `Expires ${formattedDate(link.expiresAt)}`}</p></div>{!inactive ? <Button type="button" variant="secondary" size="sm" disabled={pending} aria-label={`Revoke ${link.name}`} onClick={() => {
        setError(null);
        startTransition(async () => {
          try {
            const result = await revokeWallboardLinkAction(link.id);
            if (!result.ok) { setError(result.error); return; }
            setRevokedLinks((previous) => ({ ...previous, [link.id]: new Date().toISOString() }));
            if (issued && new URL(issued.url).searchParams.get("token")?.includes(link.id)) setIssued(null);
          } catch { setError("The link could not be revoked. Check your connection and try again."); }
        });
      }}>Revoke</Button> : null}</li>;
    })}</ul> : <p className="text-sm text-muted">No display links yet.</p>}</div>
  </section>;
}
