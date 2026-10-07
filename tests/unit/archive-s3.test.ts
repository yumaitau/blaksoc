import { afterEach, describe, expect, it } from "vitest";
import { ArchiveResidencyError, S3ArchiveStore, s3ArchiveConfigFromEnv, type S3ArchiveConfig } from "@/lib/hosting/s3-store";
import { archiveStoreFromEnv, FileArchiveStore } from "@/lib/hosting/store";
import { startS3Stub, type S3Stub, type StubObject } from "../fixtures/s3-stub";

const stubs: S3Stub[] = [];
afterEach(async () => {
  await Promise.all(stubs.splice(0).map((s) => s.close()));
});

const BUCKETS = { "blaksoc-syd": "ap-southeast-2", "blaksoc-mel": "ap-southeast-4" };
const credentials = { accessKeyId: "AKIASTUB", secretAccessKey: "stub-secret" };

async function stub(opts: { buckets?: Record<string, string>; objects?: Map<string, StubObject>; pageSize?: number } = {}) {
  const s = await startS3Stub({ buckets: opts.buckets ?? BUCKETS, objects: opts.objects, pageSize: opts.pageSize });
  stubs.push(s);
  return s;
}

function config(s: S3Stub, extra: Partial<S3ArchiveConfig> = {}): S3ArchiveConfig {
  return {
    buckets: { "ap-southeast-2": "blaksoc-syd", "ap-southeast-4": "blaksoc-mel" },
    endpoint: s.endpoint,
    forcePathStyle: true,
    sse: "AES256",
    credentials,
    ...extra,
  };
}

describe("S3 archive store", () => {
  it("round-trips both Australian regions with server-side encryption and refuses the rest", async () => {
    const s = await stub();
    const store = new S3ArchiveStore(config(s));
    await store.put("ap-southeast-2", "syslog/t1/a.log", "sydney");
    await store.put("ap-southeast-4", "syslog/t1/b.log", "melbourne");
    expect(await store.get("ap-southeast-2", "syslog/t1/a.log")).toBe("sydney");
    expect(await store.get("ap-southeast-4", "syslog/t1/b.log")).toBe("melbourne");
    expect(await store.list("ap-southeast-4", "syslog/t1/")).toEqual(["syslog/t1/b.log"]);
    expect(s.objects.get("blaksoc-syd/syslog/t1/a.log")).toEqual({ body: "sydney", sse: "AES256", kmsKeyId: null });
    // Each region's bucket is signed for that region.
    expect(s.requests.filter((r) => r.bucket === "blaksoc-mel").every((r) => r.region === "ap-southeast-4")).toBe(true);
    expect(s.requests.filter((r) => r.bucket === "blaksoc-syd").every((r) => r.region === "ap-southeast-2")).toBe(true);

    const sent = s.requests.length;
    await expect(store.put("us-east-1", "syslog/t1/c.log", "no")).rejects.toThrow(/Australia/);
    await expect(store.get("eu-central-1", "syslog/t1/a.log")).rejects.toThrow(/Australia/);
    await expect(store.put("ap-southeast-2", "../etc/passwd", "no")).rejects.toThrow(/archive key/);
    await expect(store.put("ap-southeast-2", "/syslog/t1/a.log", "no")).rejects.toThrow(/archive key/);
    expect(s.requests.length).toBe(sent);
    await expect(store.get("ap-southeast-2", "syslog/t1/missing.log")).rejects.toThrow(/missing/);

    const sydneyOnly = new S3ArchiveStore(config(s, { buckets: { "ap-southeast-2": "blaksoc-syd" } }));
    await expect(sydneyOnly.put("ap-southeast-4", "syslog/t1/c.log", "no")).rejects.toThrow(/no archive bucket/);
    expect(() => new S3ArchiveStore(config(s, { buckets: { "us-west-2": "x" } as never }))).toThrow(/Australia/);
    expect(() => new S3ArchiveStore(config(s, { endpoint: "http://169.254.169.254" }))).toThrow(/egress refused/);
  });

  it("writes the KMS key header and pages through long listings", async () => {
    const s = await stub({ pageSize: 2 });
    const store = new S3ArchiveStore(config(s, { sse: "aws:kms", kmsKeyId: "alias/blaksoc-archive" }));
    for (const n of [1, 2, 3, 4, 5]) await store.put("ap-southeast-2", `syslog/t2/${n}.log`, `line ${n}`);
    await store.put("ap-southeast-2", "syslog/t3/other.log", "other tenant");
    expect(await store.list("ap-southeast-2", "syslog/t2/")).toEqual([1, 2, 3, 4, 5].map((n) => `syslog/t2/${n}.log`));
    expect(s.requests.filter((r) => r.method === "GET" && !r.key).length).toBe(3);
    expect(s.objects.get("blaksoc-syd/syslog/t2/1.log")).toMatchObject({ sse: "aws:kms", kmsKeyId: "alias/blaksoc-archive" });
    expect(() => new S3ArchiveStore(config(s, { kmsKeyId: "alias/x" }))).toThrow(/aws:kms/);
  });

  it("keeps objects across a pod replacement", async () => {
    const objects = new Map<string, StubObject>();
    const first = await stub({ objects });
    await new S3ArchiveStore(config(first)).put("ap-southeast-4", "syslog/t4/e.log", "kept");
    await first.close();
    stubs.splice(stubs.indexOf(first), 1);
    // New pod: new client, new connection, same bucket contents.
    const second = await stub({ objects });
    const replaced = new S3ArchiveStore(config(second));
    expect(await replaced.get("ap-southeast-4", "syslog/t4/e.log")).toBe("kept");
    expect(await replaced.list("ap-southeast-4", "syslog/t4/")).toEqual(["syslog/t4/e.log"]);
  });

  it("reads bucket regions back and refuses a bucket outside its configured region", async () => {
    const s = await stub();
    expect(await new S3ArchiveStore(config(s)).verifyRegions()).toEqual({ "ap-southeast-2": "ap-southeast-2", "ap-southeast-4": "ap-southeast-4" });
    const moved = await stub({ buckets: { "blaksoc-syd": "us-east-1", "blaksoc-mel": "ap-southeast-4" } });
    await expect(new S3ArchiveStore(config(moved)).verifyRegions()).rejects.toBeInstanceOf(ArchiveResidencyError);
    const swapped = await stub({ buckets: { "blaksoc-syd": "ap-southeast-4", "blaksoc-mel": "ap-southeast-4" } });
    await expect(new S3ArchiveStore(config(swapped)).verifyRegions()).rejects.toThrow(/configured for ap-southeast-2/);
  });
});

describe("archive store selection", () => {
  it("picks S3 from the environment and validates it", () => {
    const env = {
      BLAKSOC_ARCHIVE_S3_BUCKETS: "ap-southeast-2=blaksoc-syd, ap-southeast-4=blaksoc-mel",
      BLAKSOC_ARCHIVE_S3_ENDPOINT: "https://s3.example.com.au",
      BLAKSOC_ARCHIVE_S3_ACCESS_KEY_ID: "AKIA",
      BLAKSOC_ARCHIVE_S3_SECRET_ACCESS_KEY: "secret",
    };
    expect(s3ArchiveConfigFromEnv(env)).toEqual({
      buckets: { "ap-southeast-2": "blaksoc-syd", "ap-southeast-4": "blaksoc-mel" },
      endpoint: "https://s3.example.com.au",
      forcePathStyle: true,
      sse: "AES256",
      kmsKeyId: undefined,
      credentials: { accessKeyId: "AKIA", secretAccessKey: "secret" },
    });
    // No endpoint: AWS S3 with virtual-hosted buckets and the default credential chain (IRSA, Pod Identity).
    expect(s3ArchiveConfigFromEnv({ BLAKSOC_ARCHIVE_S3_BUCKETS: "ap-southeast-2=b" })).toMatchObject({ endpoint: undefined, forcePathStyle: false, credentials: undefined });
    expect(archiveStoreFromEnv(env)).toBeInstanceOf(S3ArchiveStore);
    expect(archiveStoreFromEnv({ BLAKSOC_ARCHIVE_DIR: "/tmp/x" })).toBeInstanceOf(FileArchiveStore);
    expect(s3ArchiveConfigFromEnv({})).toBeNull();
    expect(() => s3ArchiveConfigFromEnv({ BLAKSOC_ARCHIVE_S3_BUCKETS: "us-east-1=b" })).toThrow(/Australia/);
    expect(() => s3ArchiveConfigFromEnv({ BLAKSOC_ARCHIVE_S3_BUCKETS: "ap-southeast-2" })).toThrow(/region=bucket/);
    expect(() => s3ArchiveConfigFromEnv({ BLAKSOC_ARCHIVE_S3_BUCKETS: "ap-southeast-2=b", BLAKSOC_ARCHIVE_S3_SSE: "none" })).toThrow(/AES256/);
    expect(() => s3ArchiveConfigFromEnv({ BLAKSOC_ARCHIVE_S3_BUCKETS: "ap-southeast-2=b", BLAKSOC_ARCHIVE_S3_ACCESS_KEY_ID: "AKIA" })).toThrow(/both/);
  });
});
