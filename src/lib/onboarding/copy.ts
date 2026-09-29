/** Plain-English setup copy. Reading age is measured on allCopyText(). */
export const COPY = {
  title: "Set up your group.",
  nav: "Set up.",
  analystOnly: "A Yuma IT analyst runs this setup with you.",
  startLead: "Each step is saved. You can stop and come back.",
  startButton: "Start setup.",
  save: "Save and continue.",
  finish: "Finish setup.",
  back: "Back.",
  doneTitle: "Setup is saved.",
  doneBody: "We made your group, left playbooks off, and sent a summary.",
  stepOrg: "Your group.",
  stepContacts: "Who to call.",
  stepStack: "What you use.",
  stepConnect: "Connect.",
  stepGovernance: "Data rules.",
  stepPlan: "Your plan.",
  name: "Group name.",
  abn: "ABN.",
  abnHint: "We check a short example list. We do not call the government register.",
  abnHit: "This ABN is on the example list.",
  abnMiss: "This ABN is not on the example list.",
  oric: "ORIC number.",
  oricHint: "Fill this in only if you are a CATSI corporation.",
  orgType: "Group type.",
  typeAcco: "ACCO.",
  typeAccho: "ACCHO.",
  typePbc: "Land council.",
  typeIndigenous: "Indigenous business.",
  typeOther: "Other.",
  sectors: "Sectors.",
  sectorAustralia: "Australia.",
  sectorGovernment: "Government.",
  sectorIndigenous: "Indigenous business.",
  sectorHealth: "Health.",
  sectorEssential: "Essential services.",
  sectorSmall: "Small business.",
  sectorFinance: "Finance.",
  sectorEducation: "Education.",
  headcount: "How many staff.",
  location: "Place name.",
  remote: "How remote is it.",
  remoteNo: "Not remote.",
  remoteYes: "Remote.",
  remoteVery: "Very remote.",
  link: "Link speed.",
  linkStandard: "Normal link.",
  linkLow: "Slow or satellite link.",
  primary: "Main contact.",
  afterHours: "After hours contact.",
  board: "Board or CEO contact.",
  personName: "Name.",
  channel: "Best way to reach them.",
  channelSms: "Text message.",
  channelPhone: "Phone.",
  channelEmail: "Email.",
  channelTeams: "Teams.",
  contactValue: "Number or email.",
  summaryEmail: "Email for the setup summary.",
  identity: "Where your email and files live.",
  identityM365: "Microsoft 365.",
  identityGoogle: "Google.",
  identityOther: "Something else.",
  accounting: "Accounts tool.",
  itProvider: "IT helper, if you have one.",
  connectM365: "This records sample Microsoft 365 data. It is not a live sign in.",
  connectGoogle: "Google is not connected in this step.",
  connectOther: "We did not connect another email system in this step.",
  azureId: "Microsoft tenant id, if you have it.",
  azureHint: "Leave this blank and we use a sample id.",
  domains: "Domain names, one per line.",
  domainsHint: "We store the names. We do not register them yet.",
  agents: "Phone and PC sensors come later. We do not install them now.",
  govLead: "We note the strongest data rules. They are not on yet. The advisory group has not signed them.",
  govChoice: "Use the strongest rules.",
  planLead: "Pick a plan. Prices are not on this page.",
  planEssentials: "Essentials.",
  planStandard: "Standard.",
  planPlus: "Plus.",
  nonprofit: "Not for profit.",
  emailTitle: "Your setup summary.",
  reportConnected: "What we connected.",
  reportWhy: "Why.",
  reportWhyBody: "You can see a first alert and a summary of this setup.",
  reportDomains: "Domains.",
  domainsLater: "We noted your domain names for later. We did not register them.",
  domainsNone: "You gave no domain names. We did not register any.",
  reportRules: "Data rules.",
  reportSensors: "Sensors.",
  connectedM365: "We recorded sample Microsoft 365 data so you can see a first alert. This is not a live sign in.",
  connectedGoogle: "You chose Google. We did not connect it.",
  connectedOther: "You chose another system. We did not connect it.",
  errors: {
    analyst: "A Yuma IT analyst runs this setup with you.",
    missing: "Fill in the empty fields and save again.",
    order: "Save the earlier step first.",
    owner: "This setup belongs to someone else.",
    denied: "You cannot run setup.",
    slug: "Use a shorter group name.",
    email: "The summary email did not send.",
    generic: "We could not save that step. Try again.",
  },
} as const;

function syllables(word: string): number {
  const w = word.toLowerCase().replace(/[^a-z]/g, "");
  if (!w) return 1;
  const groups = w.match(/[aeiouy]+/g);
  return groups ? groups.length : 1;
}

/** Flesch-Kincaid grade plus 5, rounded. A 12-year-old is about grade 7. */
export function readingAge(text: string): number {
  const sentences = text.split(/[.!?]+/).map((s) => s.trim()).filter(Boolean);
  const words = text.split(/\s+/).map((w) => w.replace(/[^A-Za-z']/g, "")).filter(Boolean);
  if (!sentences.length || !words.length) return 99;
  const syl = words.reduce((n, w) => n + syllables(w), 0);
  const grade = 0.39 * (words.length / sentences.length) + 11.8 * (syl / words.length) - 15.59;
  return Math.round(grade + 5);
}

function walk(value: unknown, out: string[]) {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const item of value) walk(item, out);
  else if (value && typeof value === "object") for (const item of Object.values(value)) walk(item, out);
}

/** Every user-facing string, each ending as its own sentence. */
export function allCopyText(): string {
  const parts: string[] = [];
  walk(COPY, parts);
  return parts.map((p) => (/[.!?]$/.test(p) ? p : `${p}.`)).join(" ");
}
