/** Co-brand line. The SOC name stays in the string so the portal is not white-labelled. */
export function cobrandLine(name: string, brandName: string | null | undefined): string {
  const label = brandName?.trim() || name.trim();
  return `${label} with blakSOC`;
}
