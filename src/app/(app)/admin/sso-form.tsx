"use client";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { GOOGLE_ISSUER } from "@/lib/auth/sso-policy";
import { registerSsoAction } from "./actions";

export function SsoRegisterForm({ tenants, appUrl }: { tenants: { id: string; name: string }[]; appUrl: string }) {
  const { pending, error, run } = useAction();
  const [kind, setKind] = useState<"oidc" | "google" | "saml">("oidc");
  const protocol = kind === "saml" ? "saml" : "oidc";
  const [f, setF] = useState({ providerId: "", domain: "", tenantId: "", issuer: "", clientId: "", clientSecret: "", entryPoint: "", cert: "", entraTenant: "" });
  const [ok, setOk] = useState(false);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setOk(false);
    setF((x) => ({ ...x, [k]: e.target.value }));
  };
  const base = `${appUrl}/api/auth/sso`;
  const pid = f.providerId || "<provider-id>";

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        setOk(false);
        const common = { providerId: f.providerId.trim(), domain: f.domain.trim(), tenantId: f.tenantId || null, issuer: kind === "google" ? GOOGLE_ISSUER : f.issuer.trim() };
        run(
          () => registerSsoAction(protocol === "oidc" ? { protocol, ...common, clientId: f.clientId.trim(), clientSecret: f.clientSecret } : { protocol, ...common, entryPoint: f.entryPoint.trim(), cert: f.cert.trim() }),
          () => {
            setOk(true);
            setF((x) => ({ ...x, clientSecret: "", cert: "" }));
          },
        );
      }}
    >
      <div role="radiogroup" aria-label="Protocol" className="inline-flex rounded-md border border-border p-0.5">
        {(["oidc", "google", "saml"] as const).map((p) => (
          <button key={p} type="button" role="radio" aria-checked={kind === p} onClick={() => setKind(p)} className={`rounded px-3 py-1 text-xs font-medium ${kind === p ? "bg-accent-soft text-accent" : "text-muted hover:text-fg"}`}>
            {p === "oidc" ? "OIDC (Entra ID)" : p === "google" ? "Google Workspace" : "SAML 2.0"}
          </button>
        ))}
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <div>
          <Label htmlFor="sso-id">Provider id</Label>
          <Input id="sso-id" required pattern="[a-z0-9-]{2,40}" placeholder="wattle-entra" value={f.providerId} onChange={set("providerId")} />
        </div>
        <div>
          <Label htmlFor="sso-domain">Email domain</Label>
          <Input id="sso-domain" required placeholder="wattle.com.au" value={f.domain} onChange={set("domain")} />
        </div>
        <div>
          <Label htmlFor="sso-tenant">Signs users into</Label>
          <Select id="sso-tenant" value={f.tenantId} onChange={set("tenantId")}>
            <option value="">Yuma IT staff (platform)</option>
            {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </Select>
        </div>
      </div>

      {kind === "google" ? (
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="sso-gclient">OAuth client id</Label>
            <Input id="sso-gclient" required value={f.clientId} onChange={set("clientId")} />
          </div>
          <div>
            <Label htmlFor="sso-gsecret">OAuth client secret</Label>
            <Input id="sso-gsecret" type="password" autoComplete="off" required value={f.clientSecret} onChange={set("clientSecret")} />
          </div>
          <p className="text-xs text-muted sm:col-span-2">
            In the customer&apos;s Google Cloud project, create a Web application OAuth client with the Internal audience. Authorised redirect URI: <code className="font-mono text-fg">{base}/callback/{pid}</code>. Sign-ins must carry a Workspace <code className="font-mono">hd</code> claim for the email domain above; personal Google accounts are refused.
          </p>
        </div>
      ) : kind === "oidc" ? (
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="sso-entra">Entra directory (tenant) id: fills the issuer</Label>
            <Input
              id="sso-entra"
              placeholder="00000000-0000-0000-0000-000000000000"
              value={f.entraTenant}
              onChange={(e) => {
                const v = e.target.value.trim();
                setF((x) => ({ ...x, entraTenant: v, issuer: v ? `https://login.microsoftonline.com/${v}/v2.0` : x.issuer }));
              }}
            />
          </div>
          <div>
            <Label htmlFor="sso-issuer">Issuer</Label>
            <Input id="sso-issuer" required placeholder="https://login.microsoftonline.com/<tenant-id>/v2.0" value={f.issuer} onChange={set("issuer")} />
          </div>
          <div>
            <Label htmlFor="sso-client">Client (application) id</Label>
            <Input id="sso-client" required value={f.clientId} onChange={set("clientId")} />
          </div>
          <div>
            <Label htmlFor="sso-secret">Client secret</Label>
            <Input id="sso-secret" type="password" autoComplete="off" required value={f.clientSecret} onChange={set("clientSecret")} />
          </div>
          <p className="text-xs text-muted sm:col-span-2">
            Redirect URI to register in Entra: <code className="font-mono text-fg">{base}/callback/{pid}</code>
          </p>
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="sso-entity">IdP issuer / entity id</Label>
            <Input id="sso-entity" required value={f.issuer} onChange={set("issuer")} />
          </div>
          <div>
            <Label htmlFor="sso-entry">SSO entry point URL</Label>
            <Input id="sso-entry" type="url" required placeholder="https://idp.example.com/saml2/sso" value={f.entryPoint} onChange={set("entryPoint")} />
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="sso-cert">IdP signing certificate (PEM)</Label>
            <Textarea id="sso-cert" required className="font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" value={f.cert} onChange={set("cert")} />
          </div>
          <p className="text-xs text-muted sm:col-span-2">
            ACS URL: <code className="font-mono text-fg">{base}/saml2/sp/acs/{pid}</code> · SP metadata: <code className="font-mono text-fg">{base}/saml2/sp/metadata?providerId={pid}</code>
          </p>
        </div>
      )}

      <div className="flex items-center gap-3">
        <Button type="submit" size="sm" disabled={pending}>{pending ? "Registering…" : "Register provider"}</Button>
        {ok ? <span role="status" className="text-sm text-ok">Provider registered.</span> : null}
        <ActionError error={error} />
      </div>
    </form>
  );
}
