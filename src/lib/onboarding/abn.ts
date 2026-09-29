export type AbnLookup = { abn: string; found: boolean; name: string | null };

/**
 * Checks a short example list. Does not call the ABR.
 * 51824753556 is the ATO's published example, not a customer.
 */
export function lookupAbn(raw: string): AbnLookup {
  const abn = raw.replace(/\D/g, "");
  if (abn === "51824753556") return { abn, found: true, name: "Example Business" };
  return { abn, found: false, name: null };
}
