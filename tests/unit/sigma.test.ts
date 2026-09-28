import { describe, expect, it } from "vitest";
import { attackTechniques, matches, parseSigma, runTests, SigmaError, toOpenSearchQuery } from "@/lib/detections/sigma";
import { SIGMA_RULES } from "@/db/seed/reference";

const enc = parseSigma(SIGMA_RULES[0]!);
const lsass = parseSigma(SIGMA_RULES[1]!);
const vss = parseSigma(SIGMA_RULES[2]!);
const ssh = parseSigma(SIGMA_RULES[3]!);
const win = (eventdata: Record<string, unknown>) => ({ data: { win: { eventdata } } });

describe("sigma", () => {
  it("parses ATT&CK tags", () => {
    expect(attackTechniques(enc)).toEqual(["T1059.001", "T1027"]);
  });

  it("all of selection_* requires every selection", () => {
    expect(matches(enc, win({ image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", commandLine: "powershell -nop -enc SQBFAFgA" }))).toBe(true);
    expect(matches(enc, win({ image: "C:\\x\\powershell.exe", commandLine: "powershell Get-Process" }))).toBe(false);
    expect(matches(enc, win({ image: "C:\\x\\cmd.exe", commandLine: "x -enc y" }))).toBe(false);
  });

  it("and not filter", () => {
    expect(matches(lsass, { TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1010", SourceImage: "C:\\tmp\\mimi.exe" })).toBe(true);
    expect(matches(lsass, { TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1010", SourceImage: "C:\\ProgramData\\MsMpEng.exe" })).toBe(false);
  });

  it("|contains|all and 1 of", () => {
    expect(matches(vss, win({ image: "C:\\Windows\\System32\\vssadmin.exe", commandLine: "vssadmin delete shadows /all /quiet" }))).toBe(true);
    expect(matches(vss, win({ image: "C:\\Windows\\System32\\vssadmin.exe", commandLine: "vssadmin list shadows" }))).toBe(false);
  });

  it("keyword lists search the whole event", () => {
    expect(matches(ssh, { full_log: "sshd[1]: Failed password for root from 1.2.3.4" })).toBe(true);
    expect(matches(ssh, { full_log: "Accepted publickey" })).toBe(false);
  });

  it("runTests reports pass/fail", () => {
    const r = runTests(ssh, [{ name: "hit", event: { full_log: "Failed password for x" }, expect: true }, { name: "wrong", event: { full_log: "ok" }, expect: true }]);
    expect(r.passed).toBe(false);
    expect(r.results.map((x) => x.pass)).toEqual([true, false]);
  });

  it("converts to an OpenSearch query with Wazuh field mapping", () => {
    const q = toOpenSearchQuery(enc);
    expect(q).toContain("data.win.eventdata.image:*\\\\powershell.exe");
    expect(q).toContain("data.win.eventdata.commandLine:*\\ \\-enc\\ *");
    expect(q).toMatch(/ AND /);
  });

  it("rejects invalid rules", () => {
    expect(() => parseSigma("title: x\nid: nope\nlogsource: {}\ndetection: {condition: a}")).toThrow(SigmaError);
    expect(() => parseSigma(`title: x\nid: 5e4c1f2a-7c1d-4f8b-9a2e-1b3c4d5e6f70\nlogsource: {product: x}\ndetection:\n  a: {F: 1}\n  condition: a and (`)).toThrow(SigmaError);
  });

  it("unknown selection in condition is rejected at parse time", () => {
    expect(() => parseSigma(`title: x\nid: 5e4c1f2a-7c1d-4f8b-9a2e-1b3c4d5e6f70\nlogsource: {product: x}\ndetection:\n  a: {F: 1}\n  condition: a or b`)).toThrow(/unknown selection/);
  });
});
