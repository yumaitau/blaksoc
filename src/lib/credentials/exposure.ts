export const STORED_DATA_CLASSES = ["email", "username", "password-hash"] as const;

export type RawExposure = {
  identity: string;
  breach: string;
  source: string;
  observedAt: string;
  dataClasses: string[];
  password?: string;
};

export type StoredExposure = {
  identity: string;
  breach: string;
  source: string;
  observedAt: string;
  dataClasses: string[];
};

const CLASS_MAP: Record<string, (typeof STORED_DATA_CLASSES)[number] | null> = {
  email: "email",
  "email addresses": "email",
  username: "username",
  usernames: "username",
  "password-hash": "password-hash",
  "password hashes": "password-hash",
  passwords: "password-hash",
  password: null,
  "plaintext-password": null,
};

/** Drop password material. Callers persist only source, date, and the classes below. */
export function sanitiseExposure(row: RawExposure): StoredExposure {
  const dataClasses = [...new Set(row.dataClasses.map((c) => CLASS_MAP[c.toLowerCase()]).filter((c): c is (typeof STORED_DATA_CLASSES)[number] => !!c))];
  return {
    identity: row.identity.trim().toLowerCase(),
    breach: row.breach.trim(),
    source: row.source.trim(),
    observedAt: row.observedAt,
    dataClasses,
  };
}

export function dedupeExposures(rows: StoredExposure[]): StoredExposure[] {
  const seen = new Set<string>();
  const out: StoredExposure[] = [];
  for (const row of rows) {
    const key = `${row.identity}\n${row.breach}\n${row.source}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}

/** Fixture Have I Been Pwned domain search. No network. */
export function hibpFixture(domain: string): RawExposure[] {
  if (domain === "wattle.example" || domain.endsWith(".example")) {
    return [{
      identity: `ada@${domain}`,
      breach: "Collection #1",
      source: "hibp",
      observedAt: "2024-03-01T00:00:00.000Z",
      dataClasses: ["email", "passwords"],
      password: "must-not-be-stored",
    }];
  }
  return [];
}

/** Fixture commercial infostealer rows. Entitlement gating happens before insert. */
export function infostealerFixture(domain: string): RawExposure[] {
  return [{
    identity: `ada@${domain}`,
    breach: "RedLine sample",
    source: "Infostealer Feed",
    observedAt: "2024-06-01T00:00:00.000Z",
    dataClasses: ["email", "password-hash"],
  }];
}
