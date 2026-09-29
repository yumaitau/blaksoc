import { COPY } from "@/lib/onboarding/copy";
import {
  BANDWIDTH_PROFILES, CONTACT_CHANNELS, ONBOARDING_STEPS, ORG_TYPES, REMOTE_FLAGS,
  type ConnectDraft, type ContactsDraft, type OnboardingStep, type OrgDraft, type PlanDraft, type StackDraft,
} from "@/lib/onboarding/types";
import { requireAccess } from "@/lib/auth/session";
import { SECTOR_TAGS } from "@/db/schema/platform";
import { canRunOnboarding, ownDraft } from "@/lib/services/onboarding";

export const metadata = { title: "Set up" };

const inputCls = "mt-1 w-full min-h-11 rounded-md border border-border bg-transparent px-3 text-base";

const STEP_LABEL: Record<OnboardingStep, string> = {
  org: COPY.stepOrg,
  contacts: COPY.stepContacts,
  stack: COPY.stepStack,
  connect: COPY.stepConnect,
  governance: COPY.stepGovernance,
  plan: COPY.stepPlan,
};

const ORG_LABEL: Record<(typeof ORG_TYPES)[number], string> = {
  acco: COPY.typeAcco,
  accho: COPY.typeAccho,
  pbc: COPY.typePbc,
  indigenous_business: COPY.typeIndigenous,
  other: COPY.typeOther,
};

const SECTOR_LABEL: Record<(typeof SECTOR_TAGS)[number], string> = {
  AUSTRALIA: COPY.sectorAustralia,
  GOVERNMENT: COPY.sectorGovernment,
  INDIGENOUS_BUSINESS: COPY.sectorIndigenous,
  HEALTHCARE: COPY.sectorHealth,
  CRITICAL_INFRASTRUCTURE: COPY.sectorEssential,
  SMB: COPY.sectorSmall,
  FINANCE: COPY.sectorFinance,
  EDUCATION: COPY.sectorEducation,
};

const CHANNEL_LABEL: Record<(typeof CONTACT_CHANNELS)[number], string> = {
  sms: COPY.channelSms,
  phone: COPY.channelPhone,
  email: COPY.channelEmail,
  teams: COPY.channelTeams,
};

const REMOTE_LABEL: Record<(typeof REMOTE_FLAGS)[number], string> = {
  no: COPY.remoteNo,
  remote: COPY.remoteYes,
  "very remote": COPY.remoteVery,
};

const LINK_LABEL = {
  standard: COPY.linkStandard,
  low: COPY.linkLow,
} as const;

function errorText(code: string | undefined): string | null {
  if (!code) return null;
  if (code in COPY.errors) return COPY.errors[code as keyof typeof COPY.errors];
  return COPY.errors.generic;
}

function shownStep(saved: string, requested?: string): OnboardingStep {
  const current = ONBOARDING_STEPS.includes(saved as OnboardingStep) ? (saved as OnboardingStep) : "org";
  if (requested && ONBOARDING_STEPS.includes(requested as OnboardingStep)) {
    if (ONBOARDING_STEPS.indexOf(requested as OnboardingStep) <= ONBOARDING_STEPS.indexOf(current)) return requested as OnboardingStep;
  }
  return current;
}

export default async function OnboardingPage({ searchParams }: { searchParams: Promise<{ error?: string; step?: string }> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const error = errorText(sp.error);
  if (!canRunOnboarding(ctx)) {
    return (
      <div>
        <h1 className="text-xl font-semibold">{COPY.title}</h1>
        <p className="mt-2 text-sm text-muted">{COPY.analystOnly}</p>
      </div>
    );
  }
  const draft = await ownDraft(ctx);
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">{COPY.title}</h1>
      {error ? <p className="text-sm text-muted">{error}</p> : null}
      {!draft ? <StartForm /> : draft.status === "complete" ? <Done /> : <Wizard draftId={draft.id} step={shownStep(draft.step, sp.step)} savedStep={draft.step} org={draft.org} contacts={draft.contacts} stack={draft.stack} connect={draft.connect} plan={draft.plan} />}
    </div>
  );
}

function StartForm() {
  return (
    <form action="/onboarding/save" method="post" className="space-y-4">
      <p className="text-sm text-muted">{COPY.startLead}</p>
      <input type="hidden" name="step" value="start" />
      <button className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 font-medium text-accent-fg" type="submit">{COPY.startButton}</button>
    </form>
  );
}

function Done() {
  return (
    <div>
      <h2 className="text-lg font-semibold">{COPY.doneTitle}</h2>
      <p className="mt-2 text-sm text-muted">{COPY.doneBody}</p>
    </div>
  );
}

function Wizard(props: {
  draftId: string;
  step: OnboardingStep;
  savedStep: string;
  org: OrgDraft | null;
  contacts: ContactsDraft | null;
  stack: StackDraft | null;
  connect: ConnectDraft | null;
  plan: PlanDraft | null;
}) {
  const reached = ONBOARDING_STEPS.indexOf(props.savedStep as OnboardingStep);
  return (
    <div className="space-y-4">
      <nav aria-label={COPY.title} className="flex flex-wrap gap-1">
        {ONBOARDING_STEPS.map((step, i) => i <= reached ? (
          <a key={step} className="inline-flex min-h-11 items-center px-2 underline" href={`/onboarding?step=${step}`}>{STEP_LABEL[step]}</a>
        ) : (
          <span key={step} className="inline-flex min-h-11 items-center px-2 text-sm text-muted">{STEP_LABEL[step]}</span>
        ))}
      </nav>
      <h2 className="text-lg font-semibold">{STEP_LABEL[props.step]}</h2>
      <form action="/onboarding/save" method="post" className="space-y-4">
        <input type="hidden" name="draftId" value={props.draftId} />
        <input type="hidden" name="step" value={props.step} />
        {props.step === "org" ? <OrgFields org={props.org} /> : null}
        {props.step === "contacts" ? <ContactFields contacts={props.contacts} /> : null}
        {props.step === "stack" ? <StackFields stack={props.stack} /> : null}
        {props.step === "connect" ? <ConnectFields connect={props.connect} identity={props.stack?.identity} /> : null}
        {props.step === "governance" ? <GovFields /> : null}
        {props.step === "plan" ? <PlanFields plan={props.plan} /> : null}
        <button className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 font-medium text-accent-fg" type="submit">
          {props.step === "plan" ? COPY.finish : COPY.save}
        </button>
      </form>
    </div>
  );
}

function OrgFields({ org }: { org: OrgDraft | null }) {
  const loc = org?.locations[0];
  const loc2 = org?.locations[1];
  return (
    <div className="space-y-3">
      <label className="block text-sm">{COPY.name}
        <input className={inputCls} name="name" required defaultValue={org?.name ?? ""} autoComplete="organization" />
      </label>
      <label className="block text-sm">{COPY.abn}
        <input className={inputCls} name="abn" required inputMode="numeric" defaultValue={org?.abn ?? ""} />
      </label>
      <p className="text-sm text-muted">{COPY.abnHint}</p>
      {org ? <p className="text-sm text-muted">{org.abnFound ? COPY.abnHit : COPY.abnMiss} {org.abnName ?? ""}</p> : null}
      <label className="block text-sm">{COPY.oric}
        <input className={inputCls} name="oricIcn" defaultValue={org?.oricIcn ?? ""} />
      </label>
      <p className="text-sm text-muted">{COPY.oricHint}</p>
      <label className="block text-sm">{COPY.orgType}
        <select className={inputCls} name="orgType" defaultValue={org?.orgType ?? "other"}>
          {ORG_TYPES.map((key) => <option key={key} value={key}>{ORG_LABEL[key]}</option>)}
        </select>
      </label>
      <fieldset>
        <legend className="text-sm">{COPY.sectors}</legend>
        {SECTOR_TAGS.map((tag) => (
          <label key={tag} className="mt-1 flex min-h-11 items-center gap-2 text-sm">
            <input type="checkbox" name="sectors" value={tag} defaultChecked={org?.sectors.includes(tag) ?? false} />
            {SECTOR_LABEL[tag]}
          </label>
        ))}
      </fieldset>
      <label className="block text-sm">{COPY.headcount}
        <input className={inputCls} name="headcount" required inputMode="numeric" defaultValue={org?.headcount ?? ""} />
      </label>
      <label className="block text-sm">{COPY.location}
        <input className={inputCls} name="location_1" required defaultValue={loc?.name ?? ""} />
      </label>
      <label className="block text-sm">{COPY.remote}
        <select className={inputCls} name="remote_1" defaultValue={loc?.remote ?? "no"}>
          {REMOTE_FLAGS.map((flag) => <option key={flag} value={flag}>{REMOTE_LABEL[flag]}</option>)}
        </select>
      </label>
      <label className="block text-sm">{COPY.link}
        <select className={inputCls} name="link_1" defaultValue={loc?.link ?? "standard"}>
          {BANDWIDTH_PROFILES.map((link) => <option key={link} value={link}>{LINK_LABEL[link]}</option>)}
        </select>
      </label>
      <label className="block text-sm">{COPY.location}
        <input className={inputCls} name="location_2" defaultValue={loc2?.name ?? ""} />
      </label>
      <label className="block text-sm">{COPY.remote}
        <select className={inputCls} name="remote_2" defaultValue={loc2?.remote ?? "no"}>
          {REMOTE_FLAGS.map((flag) => <option key={flag} value={flag}>{REMOTE_LABEL[flag]}</option>)}
        </select>
      </label>
      <label className="block text-sm">{COPY.link}
        <select className={inputCls} name="link_2" defaultValue={loc2?.link ?? "standard"}>
          {BANDWIDTH_PROFILES.map((link) => <option key={link} value={link}>{LINK_LABEL[link]}</option>)}
        </select>
      </label>
    </div>
  );
}

function personFields(prefix: string, title: string, person?: { name: string; channel: string; value: string }) {
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">{title}</legend>
      <label className="block text-sm">{COPY.personName}
        <input className={inputCls} name={`${prefix}Name`} required defaultValue={person?.name ?? ""} />
      </label>
      <label className="block text-sm">{COPY.channel}
        <select className={inputCls} name={`${prefix}Channel`} defaultValue={person?.channel ?? "phone"}>
          {CONTACT_CHANNELS.map((key) => <option key={key} value={key}>{CHANNEL_LABEL[key]}</option>)}
        </select>
      </label>
      <label className="block text-sm">{COPY.contactValue}
        <input className={inputCls} name={`${prefix}Value`} required defaultValue={person?.value ?? ""} />
      </label>
    </fieldset>
  );
}

function ContactFields({ contacts }: { contacts: ContactsDraft | null }) {
  return (
    <div className="space-y-4">
      {personFields("primary", COPY.primary, contacts?.primary)}
      {personFields("afterHours", COPY.afterHours, contacts?.afterHours)}
      {personFields("board", COPY.board, contacts?.board)}
      <label className="block text-sm">{COPY.summaryEmail}
        <input className={inputCls} name="summaryEmail" type="email" required defaultValue={contacts?.summaryEmail ?? ""} autoComplete="email" />
      </label>
    </div>
  );
}

function StackFields({ stack }: { stack: StackDraft | null }) {
  return (
    <div className="space-y-3">
      <fieldset>
        <legend className="text-sm">{COPY.identity}</legend>
        {(["m365", "google", "other"] as const).map((key) => (
          <label key={key} className="mt-1 flex min-h-11 items-center gap-2 text-sm">
            <input type="radio" name="identity" value={key} required defaultChecked={(stack?.identity ?? "m365") === key} />
            {key === "m365" ? COPY.identityM365 : key === "google" ? COPY.identityGoogle : COPY.identityOther}
          </label>
        ))}
      </fieldset>
      <label className="block text-sm">{COPY.accounting}
        <input className={inputCls} name="accounting" required defaultValue={stack?.accounting ?? ""} />
      </label>
      <label className="block text-sm">{COPY.itProvider}
        <input className={inputCls} name="itProvider" defaultValue={stack?.itProvider ?? ""} />
      </label>
    </div>
  );
}

function ConnectFields({ connect, identity }: { connect: ConnectDraft | null; identity?: StackDraft["identity"] }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">{identity === "google" ? COPY.connectGoogle : identity === "other" ? COPY.connectOther : COPY.connectM365}</p>
      <label className="block text-sm">{COPY.azureId}
        <input className={inputCls} name="azureTenantId" defaultValue={connect?.azureTenantId ?? ""} />
      </label>
      <p className="text-sm text-muted">{COPY.azureHint}</p>
      <label className="block text-sm">{COPY.domains}
        <textarea className={inputCls} name="domains" rows={3} defaultValue={connect?.domains.join("\n") ?? ""} />
      </label>
      <p className="text-sm text-muted">{COPY.domainsHint}</p>
      <p className="text-sm text-muted">{COPY.agents}</p>
    </div>
  );
}

function GovFields() {
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">{COPY.govLead}</p>
      <label className="flex min-h-11 items-center gap-2 text-sm">
        <input type="radio" name="choice" value="most_protective" required defaultChecked />
        {COPY.govChoice}
      </label>
    </div>
  );
}

function PlanFields({ plan }: { plan: PlanDraft | null }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">{COPY.planLead}</p>
      {(["essentials", "standard", "plus"] as const).map((tier) => (
        <label key={tier} className="flex min-h-11 items-center gap-2 text-sm">
          <input type="radio" name="tier" value={tier} required defaultChecked={(plan?.tier ?? "standard") === tier} />
          {tier === "essentials" ? COPY.planEssentials : tier === "standard" ? COPY.planStandard : COPY.planPlus}
        </label>
      ))}
      <label className="flex min-h-11 items-center gap-2 text-sm">
        <input type="checkbox" name="nonprofit" value="yes" defaultChecked={plan?.nonprofit ?? false} />
        {COPY.nonprofit}
      </label>
      <input type="hidden" name="finish" value="yes" />
    </div>
  );
}
