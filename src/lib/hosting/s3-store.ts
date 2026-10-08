import http from "node:http";
import https from "node:https";
import { GetBucketLocationCommand, GetObjectCommand, HeadBucketCommand, ListObjectsV2Command, PutObjectCommand, S3Client, S3ServiceException } from "@aws-sdk/client-s3";
import { assertEgressUrl, guardedLookup } from "@/lib/net/egress";
import { assertArchiveKey, assertAuRegion, AU_ARCHIVE_REGIONS, type AuArchiveRegion } from "@/lib/syslog/retain";
import type { ArchiveStore } from "./store";

export type S3ArchiveConfig = {
  /** One bucket per Australian region. A region without a bucket cannot be archived to. */
  buckets: Partial<Record<AuArchiveRegion, string>>;
  /** S3-compatible endpoint (MinIO, an Australian provider). Unset: AWS S3 for the region. */
  endpoint?: string;
  forcePathStyle?: boolean;
  sse: "AES256" | "aws:kms";
  kmsKeyId?: string;
  /** Key prefix inside the bucket, for a bucket shared with other systems (e.g. "blaksoc/archive/"). */
  keyPrefix?: string;
  /** Static keys. Unset: the AWS default chain (IRSA, EKS Pod Identity, instance role, AWS_* env). */
  credentials?: { accessKeyId: string; secretAccessKey: string };
};

/** Reads `BLAKSOC_ARCHIVE_S3_*`. Returns null when no bucket is configured (file driver). */
export function s3ArchiveConfigFromEnv(env: Record<string, string | undefined>): S3ArchiveConfig | null {
  const raw = env.BLAKSOC_ARCHIVE_S3_BUCKETS?.trim();
  if (!raw) return null;
  const buckets: Partial<Record<AuArchiveRegion, string>> = {};
  for (const pair of raw.split(",").map((p) => p.trim()).filter(Boolean)) {
    const [region, bucket] = pair.split("=").map((p) => p.trim());
    if (!region || !bucket) throw new Error(`BLAKSOC_ARCHIVE_S3_BUCKETS entry "${pair}" is not region=bucket`);
    assertAuRegion(region);
    buckets[region] = bucket;
  }
  const sse = env.BLAKSOC_ARCHIVE_S3_SSE || "AES256";
  if (sse !== "AES256" && sse !== "aws:kms") throw new Error(`BLAKSOC_ARCHIVE_S3_SSE must be AES256 or aws:kms, got ${sse}`);
  const accessKeyId = env.BLAKSOC_ARCHIVE_S3_ACCESS_KEY_ID;
  const secretAccessKey = env.BLAKSOC_ARCHIVE_S3_SECRET_ACCESS_KEY;
  if (!!accessKeyId !== !!secretAccessKey) throw new Error("set both BLAKSOC_ARCHIVE_S3_ACCESS_KEY_ID and BLAKSOC_ARCHIVE_S3_SECRET_ACCESS_KEY, or neither");
  const endpoint = env.BLAKSOC_ARCHIVE_S3_ENDPOINT || undefined;
  const pathStyle = env.BLAKSOC_ARCHIVE_S3_FORCE_PATH_STYLE;
  const rawPrefix = env.BLAKSOC_ARCHIVE_S3_PREFIX?.trim().replace(/^\/+/, "") ?? "";
  if (rawPrefix && !/^[A-Za-z0-9._\-/]+$/.test(rawPrefix)) throw new Error(`BLAKSOC_ARCHIVE_S3_PREFIX has unsupported characters: ${rawPrefix}`);
  const keyPrefix = rawPrefix && !rawPrefix.endsWith("/") ? `${rawPrefix}/` : rawPrefix;
  return {
    keyPrefix: keyPrefix || undefined,
    buckets,
    endpoint,
    forcePathStyle: pathStyle ? pathStyle === "true" : !!endpoint,
    sse,
    kmsKeyId: env.BLAKSOC_ARCHIVE_S3_KMS_KEY_ID || undefined,
    credentials: accessKeyId && secretAccessKey ? { accessKeyId, secretAccessKey } : undefined,
  };
}

/** A bucket that reports a region other than the one it is configured for. */
export class ArchiveResidencyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArchiveResidencyError";
  }
}

function missing(err: unknown): boolean {
  // A missing bucket is a config fault, not a missing object.
  return err instanceof S3ServiceException && err.name !== "NoSuchBucket" && (err.name === "NoSuchKey" || err.$metadata.httpStatusCode === 404);
}

/**
 * Durable archive driver for AWS S3 or an S3-compatible store. Same contract as FileArchiveStore:
 * AU regions only, keys are relative and tenant-scoped by the caller (`syslog/<tenant>/...`).
 * Every object is written with server-side encryption.
 */
export class S3ArchiveStore implements ArchiveStore {
  private readonly clients = new Map<AuArchiveRegion, S3Client>();

  constructor(private readonly config: S3ArchiveConfig) {
    for (const region of Object.keys(config.buckets)) assertAuRegion(region);
    if (!Object.keys(config.buckets).length) throw new Error("S3 archive store needs at least one bucket");
    // Operator config, not tenant input; still refuse metadata and link-local endpoints.
    if (config.endpoint) assertEgressUrl(config.endpoint, "internal");
    if (config.kmsKeyId && config.sse !== "aws:kms") throw new Error("a KMS key needs sse aws:kms");
  }

  private target(region: string): { client: S3Client; bucket: string } {
    assertAuRegion(region);
    const bucket = this.config.buckets[region];
    if (!bucket) throw new Error(`no archive bucket configured for ${region}`);
    let client = this.clients.get(region);
    if (!client) {
      const lookup = guardedLookup("internal");
      client = new S3Client({
        region,
        endpoint: this.config.endpoint,
        forcePathStyle: this.config.forcePathStyle,
        credentials: this.config.credentials,
        // S3-compatible stores often reject the newer default checksum headers.
        requestChecksumCalculation: "WHEN_REQUIRED",
        responseChecksumValidation: "WHEN_REQUIRED",
        requestHandler: { httpAgent: new http.Agent({ keepAlive: true, lookup }), httpsAgent: new https.Agent({ keepAlive: true, lookup }) },
      });
      this.clients.set(region, client);
    }
    return { client, bucket };
  }

  private objectKey(key: string): string {
    return `${this.config.keyPrefix ?? ""}${key}`;
  }

  async put(region: string, key: string, body: string): Promise<void> {
    assertArchiveKey(key);
    const { client, bucket } = this.target(region);
    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: this.objectKey(key),
        Body: body,
        ContentType: "text/plain; charset=utf-8",
        ServerSideEncryption: this.config.sse,
        SSEKMSKeyId: this.config.kmsKeyId,
      }),
    );
  }

  async get(region: string, key: string): Promise<string> {
    assertArchiveKey(key);
    const { client, bucket } = this.target(region);
    try {
      const out = await client.send(new GetObjectCommand({ Bucket: bucket, Key: this.objectKey(key) }));
      if (!out.Body) throw new Error("archive object missing");
      return await out.Body.transformToString("utf8");
    } catch (err) {
      if (missing(err)) throw new Error("archive object missing");
      throw err;
    }
  }

  async list(region: string, prefix: string): Promise<string[]> {
    const { client, bucket } = this.target(region);
    const out: string[] = [];
    let token: string | undefined;
    do {
      const page = await client.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: this.objectKey(prefix), ContinuationToken: token }));
      // Callers see archive keys, never the bucket prefix.
      for (const obj of page.Contents ?? []) if (obj.Key) out.push(obj.Key.slice(this.config.keyPrefix?.length ?? 0));
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token);
    return out.sort();
  }

  /**
   * Read each bucket's region back from the store. A bucket that reports a region outside
   * Australia is refused; a store that reports none (some S3-compatible servers) is accepted.
   */
  async verifyRegions(): Promise<Record<string, string | null>> {
    const seen: Record<string, string | null> = {};
    for (const region of AU_ARCHIVE_REGIONS) {
      if (!this.config.buckets[region]) continue;
      const { client, bucket } = this.target(region);
      // GetBucketLocation needs no list permission, so a role confined to a prefix of a shared bucket can ask.
      const location = await client.send(new GetBucketLocationCommand({ Bucket: bucket })).catch((err) => {
        if (err instanceof S3ServiceException && err.name === "NotImplemented") return null;
        throw err;
      });
      const constraint = location?.LocationConstraint;
      let actual: string | null = constraint === "EU" ? "eu-west-1" : constraint || null;
      // Empty means us-east-1 on AWS; S3-compatible stores often leave it empty and report through HeadBucket.
      if (!actual) actual = (await client.send(new HeadBucketCommand({ Bucket: bucket }))).BucketRegion ?? null;
      if (actual !== null && actual !== region) throw new ArchiveResidencyError(`archive bucket ${bucket} is in ${actual}, configured for ${region}`);
      seen[region] = actual;
    }
    return seen;
  }
}
