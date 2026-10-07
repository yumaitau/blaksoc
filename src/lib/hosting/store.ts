import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { assertArchiveKey, assertAuRegion } from "@/lib/syslog/retain";
import { S3ArchiveStore, s3ArchiveConfigFromEnv } from "./s3-store";

/** Region-keyed object store. Keys are relative paths. Drivers: local files (dev) and S3 (durable). */
export interface ArchiveStore {
  put(region: string, key: string, body: string): Promise<void>;
  get(region: string, key: string): Promise<string>;
  list(region: string, prefix: string): Promise<string[]>;
}

export class FileArchiveStore implements ArchiveStore {
  constructor(private readonly root: string) {}

  private resolve(region: string, key: string): string {
    assertAuRegion(region);
    const parts = assertArchiveKey(key);
    const full = path.resolve(this.root, region, ...parts);
    const base = path.resolve(this.root, region) + path.sep;
    if (!full.startsWith(base)) throw new Error("archive key");
    return full;
  }

  async put(region: string, key: string, body: string): Promise<void> {
    const full = this.resolve(region, key);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, body);
  }

  async get(region: string, key: string): Promise<string> {
    try {
      return await readFile(this.resolve(region, key), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") throw new Error("archive object missing");
      throw err;
    }
  }

  async list(region: string, prefix: string): Promise<string[]> {
    assertAuRegion(region);
    const base = path.resolve(this.root, region);
    const out: string[] = [];
    const walk = async (dir: string) => {
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
        throw err;
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) await walk(full);
        else {
          const key = path.relative(base, full).split(path.sep).join("/");
          if (key.startsWith(prefix)) out.push(key);
        }
      }
    };
    await walk(base);
    return out.sort();
  }
}

/** S3 when `BLAKSOC_ARCHIVE_S3_BUCKETS` is set, else the file store under `BLAKSOC_ARCHIVE_DIR`. */
export function archiveStoreFromEnv(env: Record<string, string | undefined>): ArchiveStore {
  const s3 = s3ArchiveConfigFromEnv(env);
  if (s3) return new S3ArchiveStore(s3);
  if (env.NODE_ENV === "production") {
    // The chart's default path is an emptyDir: objects die with the pod.
    console.warn("[archive] BLAKSOC_ARCHIVE_S3_BUCKETS is unset; using the local file store, which is not durable");
  }
  return new FileArchiveStore(env.BLAKSOC_ARCHIVE_DIR || path.join(tmpdir(), "blaksoc-archive"));
}

let singleton: ArchiveStore | null = null;

export function defaultArchiveStore(): ArchiveStore {
  if (!singleton) singleton = archiveStoreFromEnv(process.env);
  return singleton;
}
