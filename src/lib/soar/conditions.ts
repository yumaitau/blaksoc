export type Condition = { field: string; op: "eq" | "neq" | "gte" | "lte" | "in" | "contains"; value: unknown };

export function getPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((o, k) => (o != null && typeof o === "object" ? (o as Record<string, unknown>)[k] : undefined), obj);
}

export function evaluate(c: Condition, ctx: unknown): boolean {
  const v = getPath(ctx, c.field);
  switch (c.op) {
    case "eq": return v === c.value;
    case "neq": return v !== c.value;
    case "gte": return typeof v === "number" && v >= Number(c.value);
    case "lte": return typeof v === "number" && v <= Number(c.value);
    case "in": return Array.isArray(c.value) && c.value.includes(v);
    case "contains":
      if (Array.isArray(v)) return v.some((x) => (typeof x === "string" && typeof c.value === "string" ? x.startsWith(c.value) : x === c.value));
      return typeof v === "string" && typeof c.value === "string" && v.toLowerCase().includes(c.value.toLowerCase());
  }
}

export const allHold = (cs: Condition[], ctx: unknown) => cs.every((c) => evaluate(c, ctx));
