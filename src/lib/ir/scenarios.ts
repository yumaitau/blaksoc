export type IrScenario = {
  id: string;
  title: string;
  summary: string;
  injects: { minute: number; text: string }[];
  prompts: string[];
};

export const IR_SCENARIOS: readonly IrScenario[] = [
  {
    id: "bec-payment",
    title: "BEC payment fraud",
    summary: "Accounts receives a change of bank details from a supplier the group pays.",
    injects: [
      { minute: 0, text: "A supplier email asks accounts to pay the next invoice to a new account." },
      { minute: 20, text: "The reply address is one letter off the usual domain." },
      { minute: 45, text: "Someone is about to send the payment." },
    ],
    prompts: ["Who calls the supplier on a known number?", "Who can stop the payment?"],
  },
  {
    id: "ransomware-remote",
    title: "Ransomware at a remote site",
    summary: "A clinic that is a long drive away reports that files now end in a lock extension.",
    injects: [
      { minute: 0, text: "The remote site cannot open patient files." },
      { minute: 15, text: "The shared drive at the main site is still opening files." },
      { minute: 40, text: "Staff ask if they should turn the computers back on." },
    ],
    prompts: ["Who decides to keep that site offline?", "Where is the last backup for that site?"],
  },
  {
    id: "lost-laptop",
    title: "Lost laptop with client records",
    summary: "A worker left a laptop on a bus. It holds client records and was not encrypted.",
    injects: [
      { minute: 0, text: "The worker reports the laptop missing." },
      { minute: 25, text: "The laptop sign-in has no extra check." },
      { minute: 50, text: "A client asks whether their records left the office." },
    ],
    prompts: ["Who tells the client?", "Does this start an obligation clock?"],
  },
  {
    id: "cultural-leak",
    title: "Leaked cultural material",
    summary: "A folder of cultural material was shared to anyone with the link.",
    injects: [
      { minute: 0, text: "A link to the folder works without a sign-in." },
      { minute: 20, text: "Elders have not been told." },
      { minute: 40, text: "Someone asks for the link to be closed." },
    ],
    prompts: ["Who speaks to community before a public statement?", "Who closes the link?"],
  },
];

export function irScenarioById(id: string): IrScenario | null {
  return IR_SCENARIOS.find((scenario) => scenario.id === id) ?? null;
}
