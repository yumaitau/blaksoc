export const ONBOARDING_STEPS = ["org", "contacts", "stack", "connect", "governance", "plan"] as const;
export type OnboardingStep = (typeof ONBOARDING_STEPS)[number];

export const ORG_TYPES = ["acco", "accho", "pbc", "indigenous_business", "other"] as const;
export type OrgType = (typeof ORG_TYPES)[number];

export const CONTACT_CHANNELS = ["sms", "phone", "email", "teams"] as const;
export type ContactChannel = (typeof CONTACT_CHANNELS)[number];

export const REMOTE_FLAGS = ["no", "remote", "very remote"] as const;
export type RemoteFlag = (typeof REMOTE_FLAGS)[number];

export const BANDWIDTH_PROFILES = ["standard", "low"] as const;
export type BandwidthProfile = (typeof BANDWIDTH_PROFILES)[number];

export type OrgLocation = { name: string; remote: RemoteFlag; link: BandwidthProfile };

export type OrgDraft = {
  name: string;
  abn: string;
  abnName: string | null;
  abnFound: boolean;
  oricIcn: string | null;
  orgType: OrgType;
  sectors: string[];
  headcount: number;
  locations: OrgLocation[];
};

export type ContactPerson = { name: string; channel: ContactChannel; value: string };

export type ContactsDraft = {
  primary: ContactPerson;
  afterHours: ContactPerson;
  board: ContactPerson;
  summaryEmail: string;
};

export type StackDraft = {
  identity: "m365" | "google" | "other";
  accounting: string;
  itProvider: string;
};

export type ConnectDraft = {
  azureTenantId: string | null;
  domains: string[];
  agents: "later";
};

export type GovernanceDraft = {
  choice: "most_protective";
  enforced: false;
};

export type PlanDraft = {
  tier: "essentials" | "standard" | "plus";
  nonprofit: boolean;
};
