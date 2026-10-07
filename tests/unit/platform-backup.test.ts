import { execFile, execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { startS3Stub, type S3Stub } from "../fixtures/s3-stub";

const run = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const script = path.join(root, "deploy/backup/pg-backup.sh");
const dirs: string[] = [];
const stubs: S3Stub[] = [];

afterEach(async () => {
  await Promise.all(stubs.splice(0).map((s) => s.close()));
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

function has(cmd: string): boolean {
  try {
    execFileSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

async function dumpDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "blaksoc-backup-"));
  dirs.push(dir);
  // Binary content with bytes that are not valid UTF-8, like a real custom-format dump.
  await writeFile(path.join(dir, "blaksoc-20261007T000000Z.dump"), Buffer.from([0x50, 0x47, 0x44, 0x4d, 0xff, 0xfe, 0x00, 0x80]));
  return dir;
}

describe("postgres backup script", () => {
  it("ships the same script in the chart and parses as POSIX sh", async () => {
    const chart = await readFile(path.join(root, "deploy/helm/blaksoc/files/pg-backup.sh"), "utf8");
    expect(chart).toBe(await readFile(script, "utf8"));
    execFileSync("sh", ["-n", script]);
  });

  it("refuses a bucket region outside Australia before any upload", async () => {
    const dir = await dumpDir();
    const env = { NODE_ENV: "test" as const, PATH: process.env.PATH, BACKUP_DIR: dir, BACKUP_BUCKET: "b", BACKUP_REGION: "us-east-1" };
    await expect(run("sh", [script, "upload"], { env })).rejects.toMatchObject({ stderr: expect.stringContaining("Australia") });
  });

  it.skipIf(!has("aws"))("uploads the newest dump encrypted, checks its size and keeps the newest N", async () => {
    const s = await startS3Stub({ buckets: { "blaksoc-backup-syd": "ap-southeast-2" } });
    stubs.push(s);
    for (const day of ["20261004", "20261005", "20261006"]) {
      s.objects.set(`blaksoc-backup-syd/postgres/blaksoc-${day}T000000Z.dump`, { body: "old", sse: "AES256", kmsKeyId: null });
    }
    s.objects.set("blaksoc-backup-syd/other/keep-me", { body: "x", sse: null, kmsKeyId: null });
    const dir = await dumpDir();
    const env = {
      NODE_ENV: "test" as const,
      PATH: process.env.PATH,
      HOME: dir,
      AWS_ACCESS_KEY_ID: "AKIASTUB",
      AWS_SECRET_ACCESS_KEY: "stub-secret",
      AWS_CONFIG_FILE: path.join(dir, "none"),
      AWS_SHARED_CREDENTIALS_FILE: path.join(dir, "none"),
      AWS_EC2_METADATA_DISABLED: "true",
      BACKUP_DIR: dir,
      BACKUP_BUCKET: "blaksoc-backup-syd",
      BACKUP_REGION: "ap-southeast-2",
      BACKUP_ENDPOINT: s.endpoint,
      BACKUP_KEEP: "2",
    };
    const { stdout } = await run("sh", [script, "upload"], { env });
    expect(stdout).toContain("uploaded s3://blaksoc-backup-syd/postgres/blaksoc-20261007T000000Z.dump (8 bytes, AES256)");
    const uploaded = s.objects.get("blaksoc-backup-syd/postgres/blaksoc-20261007T000000Z.dump");
    expect(uploaded?.sse).toBe("AES256");
    expect(Buffer.from(uploaded!.body, "latin1")).toEqual(Buffer.from([0x50, 0x47, 0x44, 0x4d, 0xff, 0xfe, 0x00, 0x80]));
    expect([...s.objects.keys()].sort()).toEqual([
      "blaksoc-backup-syd/other/keep-me",
      "blaksoc-backup-syd/postgres/blaksoc-20261006T000000Z.dump",
      "blaksoc-backup-syd/postgres/blaksoc-20261007T000000Z.dump",
    ]);
    expect(s.requests.every((r) => r.region === "ap-southeast-2")).toBe(true);
  }, 60_000);
});

describe("disaster recovery chart and drill record", () => {
  it("quotes the recorded drill, labelled as a local drill", async () => {
    const drill = JSON.parse(await readFile(path.join(root, "docs/restore-drill-local.json"), "utf8")) as {
      label: string;
      ok: boolean;
      dump: { bytes: number };
      steps: { dumpMs: number; createMs: number; restoreMs: number; verifyMs: number };
      rtoMs: number;
      migrations: { applied: number; pending: string[] };
      audit: { ok: boolean; checked: number };
      countsMatch: boolean;
    };
    const doc = await readFile(path.join(root, "docs/disaster-recovery.md"), "utf8");
    expect(drill.label).toMatch(/local dev drill/);
    expect(drill.ok && drill.audit.ok && drill.countsMatch).toBe(true);
    expect(drill.migrations.pending).toEqual([]);
    expect(drill.rtoMs).toBe(drill.steps.createMs + drill.steps.restoreMs + drill.steps.verifyMs);
    for (const value of [drill.dump.bytes, drill.steps.dumpMs, drill.steps.createMs, drill.steps.restoreMs, drill.steps.verifyMs, drill.rtoMs, drill.audit.checked, drill.migrations.applied]) {
      expect(doc).toContain(String(value));
    }
    expect(doc).toContain("Local dev drill, not production");
    expect(doc).toContain("The first production drill has not been run");
  });

  it.skipIf(!has("helm"))("renders the backup CronJob and S3 archive env, and refuses non-AU regions", async () => {
    const chart = path.join(root, "deploy/helm/blaksoc");
    const base = ["template", "t", chart, "-f", path.join(chart, "values.yaml")];
    const plain = execFileSync("helm", base, { encoding: "utf8" });
    expect(plain).not.toContain("kind: CronJob");
    expect(plain).not.toContain("BLAKSOC_ARCHIVE_S3_BUCKETS");
    const on = execFileSync("helm", [...base, "--set", "backup.enabled=true", "--set", "backup.bucket=blaksoc-backup-syd", "--set", "archive.s3.buckets.ap-southeast-4=blaksoc-archive-mel"], { encoding: "utf8" });
    expect(on).toContain("kind: CronJob");
    expect(on).toContain('value: "ap-southeast-4=blaksoc-archive-mel"');
    expect(on).toContain('{ name: BACKUP_REGION, value: "ap-southeast-2" }');
    expect(() => execFileSync("helm", [...base, "--set", "backup.enabled=true", "--set", "backup.bucket=b", "--set", "backup.region=us-east-1"], { stdio: "pipe" })).toThrow(/ap-southeast-2 or ap-southeast-4/);
    expect(() => execFileSync("helm", [...base, "--set", "archive.s3.buckets.eu-west-1=b"], { stdio: "pipe" })).toThrow(/ap-southeast-2 or ap-southeast-4/);
  });
});
