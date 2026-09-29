/** Domain names the tenant asked us to watch. This does not register them with a registrar. */
export function parseDomainList(value: string): string[] {
  const domains = [...new Set(value.split(/[\s,]+/).map((d) => d.trim().toLowerCase()).filter(Boolean))];
  if (!domains.length || domains.length > 20) throw new Error("domain");
  for (const domain of domains) {
    if (domain.length > 253 || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new Error("domain");
  }
  return domains;
}
