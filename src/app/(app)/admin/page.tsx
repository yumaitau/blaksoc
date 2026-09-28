import { Lock } from "lucide-react";
import Link from "next/link";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { SECTOR_TAGS } from "@/db/schema";
import { can, type AccessContext } from "@/lib/auth/access";
import { PERMISSIONS } from "@/lib/auth/permissions";
import { requireAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { listRoles, listSsoProviders, listTenants, listUsers } from "@/lib/services/admin";
import { cn, fmtDateTime } from "@/lib/utils";
import { CreateTenantForm, TenantSettingsForm } from "./customer-forms";
import { CreateRoleForm } from "./role-form";
import { SsoRegisterForm } from "./sso-form";
import { AssignRoleForm, DisableButton, RevokeButton } from "./user-forms";

export const metadata = { title: "Administration" };

const TABS = [
  { key: "customers", label: "Customers" },
  { key: "users", label: "Users & access" },
  { key: "roles", label: "Roles" },
  { key: "identity", label: "Identity providers" },
] as const;
type Tab = (typeof TABS)[number]["key"];

function Denied({ children }: { children: React.ReactNode }) {
  return (
    <div role="status" className="flex items-start gap-3 rounded-lg border border-border bg-surface px-4 py-3 text-sm">
      <Lock className="mt-0.5 size-4 shrink-0 text-faint" />
      <div className="text-muted">{children}</div>
    </div>
  );
}

function perms(ctx: AccessContext) {
  return {
    createTenant: ctx.isPlatform && can(ctx, "tenant:manage"),
    settings: ctx.tenants.some((t) => can(ctx, "settings:manage", t.id)),
    users: can(ctx, "user:manage"),
    platformUsers: ctx.isPlatform && can(ctx, "user:manage"),
    identity: ctx.isPlatform && can(ctx, "settings:manage"),
  };
}

export default async function AdminPage({ searchParams }: { searchParams: Promise<{ tab?: string; tenant?: string }> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const p = perms(ctx);

  if (!p.createTenant && !p.settings && !p.users && !p.identity) {
    return (
      <>
        <PageHeader eyebrow="Govern" title="Administration" />
        <EmptyState title="Administration is restricted">
          Managing customers, users, roles and identity providers needs the tenant, user or settings management permission. Your role doesn&apos;t include these.
          {can(ctx, "audit:read") ? <> You can still review the <Link href="/admin/audit" className="text-accent hover:underline">audit trail</Link>.</> : null}
        </EmptyState>
      </>
    );
  }

  const fallback: Tab = p.settings || p.createTenant ? "customers" : p.users ? "users" : "identity";
  const tab: Tab = TABS.some((t) => t.key === sp.tab) ? (sp.tab as Tab) : fallback;

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Govern"
        title="Administration"
        description="Customers, access and identity. Every change here is written to the tamper-evident audit trail."
        actions={can(ctx, "audit:read") ? <Link href="/admin/audit" className="text-xs text-accent hover:underline">Audit trail →</Link> : undefined}
      />
      <nav aria-label="Administration sections" className="flex gap-1 border-b border-border">
        {TABS.map((t) => (
          <Link
            key={t.key}
            href={`/admin?tab=${t.key}`}
            aria-current={tab === t.key ? "page" : undefined}
            className={cn("-mb-px border-b-2 px-3 py-2 text-sm", tab === t.key ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg")}
          >
            {t.label}
          </Link>
        ))}
      </nav>
      {tab === "customers" ? <Customers ctx={ctx} p={p} selected={sp.tenant} /> : null}
      {tab === "users" ? <Users ctx={ctx} p={p} /> : null}
      {tab === "roles" ? <Roles p={p} /> : null}
      {tab === "identity" ? <Identity ctx={ctx} p={p} /> : null}
    </div>
  );
}

type P = ReturnType<typeof perms>;

async function Customers({ ctx, p, selected }: { ctx: AccessContext; p: P; selected?: string }) {
  const tenants = await listTenants(ctx);
  const editable = tenants.filter((t) => can(ctx, "settings:manage", t.id));
  const current = editable.find((t) => t.id === selected) ?? null;
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Customers</CardTitle>
          <span className="text-xs text-muted">{tenants.length} tenants</span>
        </CardHeader>
        <Table>
          <THead>
            <TR className="hover:bg-transparent"><TH>Name</TH><TH>Slug</TH><TH>Kind</TH><TH>Deployment</TH><TH>Sectors</TH><TH>AI</TH><TH>Auto-containment</TH><TH /></TR>
          </THead>
          <TBody>
            {tenants.map((t) => (
              <TR key={t.id} className={cn(t.id === current?.id && "bg-surface-2/60")}>
                <TD className="font-medium">{t.name}</TD>
                <TD className="font-mono text-xs text-muted">{t.slug}</TD>
                <TD><Badge variant={t.kind === "mssp" ? "accent" : "outline"}>{t.kind}</Badge></TD>
                <TD className="text-xs text-muted">{t.deploymentMode}</TD>
                <TD className="max-w-56 truncate text-xs text-muted">{t.sectors.map((s) => s.toLowerCase().replaceAll("_", " ")).join(", ") || "—"}</TD>
                <TD>{t.settings.ai.enabled ? <Badge variant="ok">on</Badge> : <Badge>off</Badge>}</TD>
                <TD>{t.settings.autoContainment ? <Badge variant="danger">ON</Badge> : <span className="text-xs text-faint">off</span>}</TD>
                <TD className="text-right">
                  {can(ctx, "settings:manage", t.id) ? <Link href={`/admin?tab=customers&tenant=${t.id}`} className="text-xs text-accent hover:underline">Settings</Link> : null}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </Card>

      {current ? (
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Settings · {current.name}</CardTitle>
              <CardDescription>Sharing, AI and SLA policy for this customer.</CardDescription>
            </div>
            <Link href="/admin?tab=customers" className="text-xs text-muted hover:text-fg">Close</Link>
          </CardHeader>
          <CardContent>
            <TenantSettingsForm key={current.id} tenantId={current.id} initial={current.settings} canAutoContainment={p.createTenant} />
          </CardContent>
        </Card>
      ) : !p.settings ? (
        <Denied>Changing customer settings needs the settings management permission.</Denied>
      ) : null}

      {p.createTenant ? (
        <Card>
          <CardHeader><CardTitle>Add a customer</CardTitle></CardHeader>
          <CardContent><CreateTenantForm sectors={SECTOR_TAGS} /></CardContent>
        </Card>
      ) : (
        <Denied>Only platform administrators can add customers.</Denied>
      )}
    </div>
  );
}

async function Users({ ctx, p }: { ctx: AccessContext; p: P }) {
  if (!p.users) return <Denied>Managing users and role assignments needs the user management permission.</Denied>;
  const [users, roles] = await Promise.all([listUsers(ctx), listRoles()]);
  const tenantName = new Map(ctx.tenants.map((t) => [t.id, t.name]));
  const assignable = roles.filter((r) => r.scope === "tenant" || p.platformUsers);
  const assignTenants = ctx.tenants.filter((t) => can(ctx, "user:manage", t.id));
  const canRevoke = (tenantId: string | null) => (tenantId ? can(ctx, "user:manage", tenantId) : p.platformUsers);

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader><CardTitle>Assign a role</CardTitle></CardHeader>
        <CardContent>
          {users.length ? (
            <AssignRoleForm
              users={users.map((u) => ({ id: u.id, label: `${u.name} · ${u.email}` }))}
              roles={assignable.map((r) => ({ key: r.key, name: r.name, scope: r.scope }))}
              tenants={assignTenants.map((t) => ({ id: t.id, name: t.name }))}
            />
          ) : (
            <p className="text-sm text-muted">No users in your scope yet. Users appear after their first SSO sign-in.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
          <span className="text-xs text-muted">{users.length} users{p.platformUsers ? "" : " in your organisation"}</span>
        </CardHeader>
        <Table>
          <THead>
            <TR className="hover:bg-transparent"><TH>User</TH><TH>Security</TH><TH>Roles</TH><TH>Created</TH>{p.platformUsers ? <TH className="text-right">Account</TH> : null}</TR>
          </THead>
          <TBody>
            {users.map((u) => (
              <TR key={u.id} className={cn(u.disabled && "opacity-60")}>
                <TD>
                  <div className="font-medium">{u.name}</div>
                  <div className="text-xs text-muted">{u.email}</div>
                </TD>
                <TD>
                  <div className="flex flex-wrap gap-1">
                    {u.isBreakGlass ? <Badge variant="danger">break-glass</Badge> : null}
                    {u.twoFactorEnabled ? <Badge variant="ok">MFA</Badge> : <Badge variant={u.isBreakGlass ? "danger" : "outline"}>no MFA</Badge>}
                    {u.disabled ? <Badge variant="warn">disabled</Badge> : null}
                  </div>
                </TD>
                <TD>
                  {u.assignments.length === 0 ? (
                    <span className="text-xs text-faint">No roles: access pending</span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {u.assignments.map((a) => {
                        const label = `${a.roleName}${a.tenantId ? ` @ ${tenantName.get(a.tenantId) ?? "other tenant"}` : " (platform)"}`;
                        return (
                          <span key={a.id} className="inline-flex items-center rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[11px]">
                            {label}
                            {canRevoke(a.tenantId) ? <RevokeButton assignmentId={a.id} label={`${label} from ${u.name}`} /> : null}
                          </span>
                        );
                      })}
                    </div>
                  )}
                </TD>
                <TD className="whitespace-nowrap text-xs text-muted">{fmtDateTime(u.createdAt)}</TD>
                {p.platformUsers ? (
                  <TD>{u.id === ctx.principal.userId ? <span className="block text-right text-xs text-faint">you</span> : <DisableButton userId={u.id} disabled={!!u.disabled} name={u.name} />}</TD>
                ) : null}
              </TR>
            ))}
          </TBody>
        </Table>
      </Card>
    </div>
  );
}

async function Roles({ p }: { p: P }) {
  const roles = await listRoles();
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Permission matrix</CardTitle>
            <CardDescription>Platform roles reach every customer; tenant roles are confined to one.</CardDescription>
          </div>
        </CardHeader>
        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full border-collapse text-xs">
            <thead className="sticky top-0 z-10 bg-surface">
              <tr className="border-b border-border">
                <th className="sticky left-0 bg-surface px-3 py-2 text-left font-medium text-faint">Permission</th>
                {roles.map((r) => (
                  <th key={r.key} scope="col" className="px-2 py-2 text-center align-bottom font-medium" title={r.description ?? undefined}>
                    <div className="max-w-24 text-[11px] leading-tight">{r.name}</div>
                    <div className="mt-1 flex justify-center gap-1">
                      <Badge variant={r.scope === "platform" ? "accent" : "outline"}>{r.scope}</Badge>
                      {r.builtin ? null : <Badge variant="intel">custom</Badge>}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {PERMISSIONS.map((perm) => (
                <tr key={perm} className="border-b border-border last:border-0 hover:bg-surface-2/60">
                  <th scope="row" className="sticky left-0 bg-surface px-3 py-1 text-left font-mono font-normal text-muted">{perm}</th>
                  {roles.map((r) => (
                    <td key={r.key} className="px-2 py-1 text-center">
                      {r.permissions.includes(perm) ? <span className="text-ok" aria-label="granted">●</span> : <span className="text-faint/40" aria-label="not granted">·</span>}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      {p.platformUsers ? (
        <Card>
          <CardHeader><CardTitle>Create a custom role</CardTitle></CardHeader>
          <CardContent><CreateRoleForm permissions={PERMISSIONS} /></CardContent>
        </Card>
      ) : (
        <Denied>Only platform administrators with user management can create custom roles.</Denied>
      )}
    </div>
  );
}

async function Identity({ ctx, p }: { ctx: AccessContext; p: P }) {
  if (!p.identity) return <Denied>Identity providers are managed by platform administrators with the settings management permission.</Denied>;
  const [providers, tenants] = await Promise.all([listSsoProviders(ctx), listTenants(ctx)]);
  const tenantName = new Map(tenants.map((t) => [t.id, t.name]));
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Registered identity providers</CardTitle>
          <span className="text-xs text-muted">Users are matched to a provider by email domain</span>
        </CardHeader>
        {providers.length === 0 ? (
          <div className="p-4"><EmptyState title="No SSO providers">Register the Yuma IT Entra ID tenant first, then one per customer that signs in with its own IdP.</EmptyState></div>
        ) : (
          <Table>
            <THead><TR className="hover:bg-transparent"><TH>Provider id</TH><TH>Protocol</TH><TH>Issuer</TH><TH>Domain</TH><TH>Signs into</TH><TH>Registered</TH></TR></THead>
            <TBody>
              {providers.map((s) => (
                <TR key={s.id}>
                  <TD className="font-mono text-xs">{s.providerId}</TD>
                  <TD><Badge variant="outline">{s.saml ? "SAML" : "OIDC"}</Badge></TD>
                  <TD className="max-w-72 truncate font-mono text-xs text-muted" title={s.issuer}>{s.issuer}</TD>
                  <TD className="text-xs">{s.domain}</TD>
                  <TD className="text-xs">{s.tenantId ? tenantName.get(s.tenantId) ?? s.tenantId : <Badge variant="accent">Yuma IT staff</Badge>}</TD>
                  <TD className="whitespace-nowrap text-xs text-muted">{fmtDateTime(s.createdAt)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Register a provider</CardTitle>
            <CardDescription>Registration goes through the SSO plugin, which only accepts platform administrators.</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <SsoRegisterForm tenants={tenants.filter((t) => t.kind === "customer").map((t) => ({ id: t.id, name: t.name }))} appUrl={env().APP_URL} />
        </CardContent>
      </Card>
    </div>
  );
}
