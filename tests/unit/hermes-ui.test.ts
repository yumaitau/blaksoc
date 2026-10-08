import { describe, expect, it } from "vitest";
import { HERMES_CLOSURE_LABEL, hermesActionHref, hermesClosure, parseHermesAction, parseHermesFilter, runOutcome } from "@/lib/tuning/hermes-ui";

const ACTION = "6f0c3a52-8e1d-4b8a-9a43-1f2d3c4b5a69";

describe("queue filters", () => {
  it("accepts only the known Hermes filters", () => {
    expect(parseHermesFilter("closed")).toBe("closed");
    expect(parseHermesFilter("annotated")).toBe("annotated");
    expect(parseHermesFilter("any")).toBe("any");
    expect(parseHermesFilter("")).toBeUndefined();
    expect(parseHermesFilter("CLOSED")).toBeUndefined();
    expect(parseHermesFilter(undefined)).toBeUndefined();
  });

  it("accepts a tuning action id and nothing else", () => {
    expect(parseHermesAction(ACTION)).toBe(ACTION);
    expect(parseHermesAction(ACTION.toUpperCase())).toBe(ACTION);
    expect(parseHermesAction("1 or 1=1")).toBeUndefined();
    expect(parseHermesAction(`${ACTION}x`)).toBeUndefined();
    expect(parseHermesAction(undefined)).toBeUndefined();
  });
});

describe("hermesClosure", () => {
  it("says whether Hermes' closure still stands", () => {
    expect(hermesClosure({ tuningActionId: null, status: "FALSE_POSITIVE" })).toBeNull();
    expect(hermesClosure({ tuningActionId: ACTION, status: "FALSE_POSITIVE", hermesUndoneAt: null })).toBe("closed");
    expect(hermesClosure({ tuningActionId: ACTION, status: "TRIAGING", hermesUndoneAt: null })).toBe("reopened");
    expect(hermesClosure({ tuningActionId: ACTION, status: "NEW", hermesUndoneAt: new Date() })).toBe("undone");
    expect(HERMES_CLOSURE_LABEL.closed).toBe("Closed by Hermes");
  });
});

describe("hermesActionHref", () => {
  it("links to the alerts an action touched; purged alerts are gone", () => {
    expect(hermesActionHref({ id: ACTION, kind: "close" })).toBe(`/soc/alerts?hermesAction=${ACTION}`);
    expect(hermesActionHref({ id: ACTION, kind: "noise_rule" })).toBe(`/soc/alerts?hermesAction=${ACTION}`);
    expect(hermesActionHref({ id: ACTION, kind: "annotate" })).toBe(`/soc/alerts?hermesAction=${ACTION}`);
    expect(hermesActionHref({ id: ACTION, kind: "purge" })).toBeNull();
  });
});

describe("runOutcome", () => {
  it("summarises the last run's report", () => {
    expect(runOutcome({ executed: 3, refused: 1, dryRun: 0, patternsReviewed: 40 })).toBe("3 executed · 1 refused by guardrails · 40 patterns reviewed");
    expect(runOutcome({ executed: 0, refused: 0, dryRun: 1, patternsReviewed: 1 })).toBe("0 executed · 0 refused by guardrails · 1 dry run · 1 pattern reviewed");
    expect(runOutcome({ executed: "x" } as never)).toBe("0 executed · 0 refused by guardrails · 0 patterns reviewed");
    expect(runOutcome(null)).toBe("No report yet");
  });
});
