/**
 * Restore drill: newest Postgres dump → scratch database → migration and smoke checks → timing JSON.
 *
 *   tsx --env-file-if-exists=.env.local scripts/restore-drill.ts [options]
 *     --fresh-dump <dir>   first run deploy/backup/pg-backup.sh dump against DATABASE_ADMIN_URL into <dir>
 *     --dump <file|dir>    restore this dump, or the newest blaksoc-*.dump in the directory
 *     --s3 <dir>           download the newest dump from BACKUP_BUCKET/BACKUP_PREFIX (BACKUP_REGION,
 *                          BACKUP_ENDPOINT, AWS default credentials) into <dir> and restore it
 *     --target <name>      scratch database on the DATABASE_ADMIN_URL server (default blaksoc_drill_restore)
 *     --compare            also count the same tables in the source database (quiet source only)
 *     --keep               leave the scratch database in place
 *     --label <text>       recorded with the result, e.g. "local dev drill"
 *     --out <file>         write the result JSON here (default: stdout only)
 *
 * The scratch database is dropped and recreated; it must not be the source database.
 * Exit code 1 when the audit chain fails, a migration is pending, the system role (DATABASE_SYSTEM_URL,
 * pointed at the scratch database) cannot see every tenant, or --compare counts differ.
 */
import { execFile, spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { arch, cpus, platform, totalmem } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { promisify } from "node:util";
import { GetObjectCommand, ListObjectsV2Command, S3Client } from "@aws-sdk/client-s3";
import postgres from "postgres";
import { assertAuRegion } from "@/lib/syslog/retain";

const run = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, "..");
/** Row counts that prove the restored platform has its tenants, people, signal and evidence. */
const SMOKE_TABLES = ["tenants", "user", "role_assignments", "integrations", "assets", "alerts", "incidents", "evidence", "audit_log", "syslog_archive"];

type Args = { freshDump?: string; dump?: string; s3?: string; target: string; compare: boolean; keep: boolean; label: string; out?: string };

function parseArgs(argv: string[]): Args {
  const args: Args = { target: "blaksoc_drill_restore", compare: false, keep: false, label: "restore drill" };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = () => {
      const v = argv[++i];
      if (!v) throw new Error(`${flag} needs a value`);
      return v;
    };
    if (flag === "--fresh-dump") args.freshDump = value();
    else if (flag === "--dump") args.dump = value();
    else if (flag === "--s3") args.s3 = value();
    else if (flag === "--target") args.target = value();
    else if (flag === "--compare") args.compare = true;
    else if (flag === "--keep") args.keep = true;
    else if (flag === "--label") args.label = value();
    else if (flag === "--out") args.out = value();
    else throw new Error(`unknown option ${flag}`);
  }
  return args;
}

/** libpq env for a URL, so passwords stay out of argv. */
function pgEnv(url: URL, database: string): NodeJS.ProcessEnv {
  return {
    ...process.env,
    PGHOST: url.hostname,
    PGPORT: url.port || "5432",
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: database,
  };
}

async function newestDump(fileOrDir: string): Promise<string> {
  if (!(await stat(fileOrDir)).isDirectory()) return fileOrDir;
  const dumps = (await readdir(fileOrDir)).filter((f) => /^blaksoc-.*\.dump$/.test(f)).sort();
  if (!dumps.length) throw new Error(`no blaksoc-*.dump in ${fileOrDir}`);
  return path.join(fileOrDir, dumps.at(-1)!);
}

async function fetchFromS3(dir: string): Promise<string> {
  const bucket = process.env.BACKUP_BUCKET;
  const region = process.env.BACKUP_REGION ?? "ap-southeast-2";
  const prefix = process.env.BACKUP_PREFIX ?? "postgres/";
  if (!bucket) throw new Error("set BACKUP_BUCKET");
  assertAuRegion(region);
  const endpoint = process.env.BACKUP_ENDPOINT || undefined;
  const client = new S3Client({ region, endpoint, forcePathStyle: !!endpoint });
  const keys: string[] = [];
  let token: string | undefined;
  do {
    const page = await client.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: `${prefix}blaksoc-`, ContinuationToken: token }));
    for (const obj of page.Contents ?? []) if (obj.Key?.endsWith(".dump")) keys.push(obj.Key);
    token = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (token);
  const key = keys.sort().at(-1);
  if (!key) throw new Error(`no dump under s3://${bucket}/${prefix}`);
  await mkdir(dir, { recursive: true });
  const file = path.join(dir, path.basename(key));
  const out = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  await pipeline(out.Body as Readable, createWriteStream(file));
  return file;
}

async function timed<T>(fn: () => Promise<T>): Promise<[T, number]> {
  const started = performance.now();
  const value = await fn();
  return [value, Math.round(performance.now() - started)];
}

async function counts(sql: postgres.Sql): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const table of SMOKE_TABLES) {
    const [row] = await sql<{ n: number }[]>`select count(*)::int as n from ${sql(table)}`;
    out[table] = row!.n;
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const adminUrl = process.env.DATABASE_ADMIN_URL;
  if (!adminUrl) throw new Error("set DATABASE_ADMIN_URL (owner of the server the scratch database is created on)");
  const server = new URL(adminUrl);
  const source = decodeURIComponent(server.pathname.slice(1));
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(args.target)) throw new Error(`invalid target database name ${args.target}`);
  if (args.target === source || ["postgres", "template0", "template1"].includes(args.target)) throw new Error(`refusing to overwrite ${args.target}`);
  const startedAt = new Date().toISOString();
  const steps: Record<string, number> = {};

  let file: string;
  if (args.freshDump) {
    const [out, ms] = await timed(() =>
      run("sh", [path.join(ROOT, "deploy/backup/pg-backup.sh"), "dump"], { env: { ...process.env, BACKUP_DATABASE_URL: adminUrl, BACKUP_DIR: args.freshDump } }),
    );
    steps.dumpMs = ms;
    process.stderr.write(out.stdout);
    file = await newestDump(args.freshDump);
  } else if (args.s3) {
    [file, steps.fetchMs] = await timed(() => fetchFromS3(args.s3!));
  } else if (args.dump) {
    file = await newestDump(args.dump);
  } else {
    throw new Error("pass --fresh-dump, --dump or --s3");
  }
  const dumpBytes = (await stat(file)).size;

  const admin = postgres(adminUrl, { max: 1, onnotice: () => {} });
  const [{ version } = { version: "" }] = await admin<{ version: string }[]>`select current_setting('server_version') as version`;
  [, steps.createMs] = await timed(async () => {
    await admin.unsafe(`drop database if exists ${args.target} with (force)`);
    await admin.unsafe(`create database ${args.target}`);
  });

  [, steps.restoreMs] = await timed(
    () =>
      new Promise<void>((resolve, reject) => {
        const child = spawn("pg_restore", ["--exit-on-error", "--dbname", args.target, file], { env: pgEnv(server, args.target), stdio: ["ignore", "inherit", "inherit"] });
        child.on("error", reject);
        child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`pg_restore exited ${code}`))));
      }),
  );

  const scratchUrl = new URL(adminUrl);
  scratchUrl.pathname = `/${args.target}`;
  const scratch = postgres(scratchUrl.toString(), { max: 1, onnotice: () => {} });
  const [verify, verifyMs] = await timed(async () => {
    // Drizzle applies an entry when its `when` is newer than the newest applied row.
    const journal = JSON.parse(await readFile(path.join(ROOT, "drizzle/meta/_journal.json"), "utf8")) as { entries: { tag: string; when: number }[] };
    const applied = await scratch<{ created_at: string }[]>`select created_at from drizzle.__drizzle_migrations`;
    const newest = Math.max(0, ...applied.map((r) => Number(r.created_at)));
    const pending = journal.entries.filter((e) => e.when > newest).map((e) => e.tag);
    const [audit] = await scratch<{ ok: boolean; checked: string; first_bad_id: string | null }[]>`select * from audit_log_verify()`;
    const restored = await counts(scratch);
    // The worker's role must still log in and see every tenant through its RLS policy: grants and policies came back.
    let systemRole: { tenants: number; ok: boolean } | null = null;
    if (process.env.DATABASE_SYSTEM_URL) {
      const url = new URL(process.env.DATABASE_SYSTEM_URL);
      url.pathname = `/${args.target}`;
      const system = postgres(url.toString(), { max: 1, onnotice: () => {} });
      const [row] = await system<{ n: number }[]>`select count(*)::int as n from tenants`;
      await system.end();
      systemRole = { tenants: row!.n, ok: row!.n === restored.tenants };
    }
    return {
      migrations: { applied: applied.length, journal: journal.entries.length, pending },
      audit: { ok: audit!.ok, checked: Number(audit!.checked), firstBadId: audit!.first_bad_id },
      systemRole,
      counts: restored,
    };
  });
  steps.verifyMs = verifyMs;
  await scratch.end();

  const sourceCounts = args.compare ? await counts(admin) : undefined;
  const countsMatch = sourceCounts ? SMOKE_TABLES.every((t) => sourceCounts[t] === verify.counts[t]) : null;

  if (!args.keep) [, steps.dropMs] = await timed(() => admin.unsafe(`drop database ${args.target} with (force)`));
  await admin.end();

  // RTO for the data tier: empty database to verified restore.
  const rtoMs = steps.createMs! + steps.restoreMs! + steps.verifyMs!;
  const ok = verify.audit.ok && verify.migrations.pending.length === 0 && verify.systemRole?.ok !== false && countsMatch !== false;
  const result = {
    label: args.label,
    startedAt,
    ok,
    host: { platform: platform(), arch: arch(), cpus: cpus().length, memoryBytes: totalmem(), postgres: version },
    dump: { file: path.basename(file), bytes: dumpBytes },
    target: args.target,
    kept: args.keep,
    steps,
    rtoMs,
    ...verify,
    sourceCounts,
    countsMatch,
  };
  const json = `${JSON.stringify(result, null, 2)}\n`;
  if (args.out) await writeFile(args.out, json);
  process.stdout.write(json);
  if (!ok) process.exit(1);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
