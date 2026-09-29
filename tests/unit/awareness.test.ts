import { describe, expect, it } from "vitest";
import { AWARENESS_LESSONS, AWARENESS_REVIEW } from "@/lib/awareness/lessons";
import { awarenessBody, boardSections } from "@/lib/reports/board";

describe("awareness lessons", () => {
  it("ships three lessons and does not claim an advisory review", () => {
    expect(AWARENESS_LESSONS.map((lesson) => lesson.id)).toEqual(["bank-change", "surprise-link", "own-signin"]);
    expect(AWARENESS_LESSONS.every((lesson) => lesson.title.length > 0 && lesson.body.length > 0)).toBe(true);
    expect(AWARENESS_REVIEW).toBe("These lessons have not been reviewed by an advisory group.");
  });

  it("puts only counts on the board section", () => {
    const body = awarenessBody(1, 3);
    expect(body).toBe("One practice send was scheduled. 3 practice clicks were recorded. No person is named here.");
    const sections = boardSections({
      light: "steady",
      openCritical: 0,
      openHigh: 0,
      openHealth: 0,
      openExploited: 0,
      newProblems: 0,
      actionPhrases: [],
      exercises: 0,
      awareness: { sends: 1, clicks: 3 },
      assessment: null,
      preamble: null,
      links: {
        problems: [],
        health: null,
        flaws: null,
        essentialEight: { label: "Essential Eight check", href: "/portal/essential-eight" },
      },
    });
    const section = sections.find((item) => item.heading === "Awareness");
    expect(section?.body).toBe(body);
    expect(section?.body).not.toMatch(/@/);
  });
});
