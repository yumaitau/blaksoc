import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir, cpus, totalmem, platform, arch } from "node:os";
import path from "node:path";
import { FileArchiveStore } from "@/lib/hosting/store";

const LINES_PER_TENANT = 20;
const TENANTS = [10, 50, 200];

const K6 = `
import http from "k6/http";
import { check } from "k6";
import exec from "k6/execution";

const lines = Number(__ENV.LINES);
export const options = {
  vus: 4,
  iterations: lines,
  thresholds: { checks: ["rate==1"], http_req_failed: ["rate==0"] },
};

export default function () {
  const n = exec.scenario.iterationInTest;
  const key = "syslog/load/" + n + ".log";
  const body = "hosting-load " + String(n).padStart(8, "0") + " " + "a".repeat(180);
  const put = http.post(__ENV.BASE + "/put", JSON.stringify({ region: "ap-southeast-2", key, body }), { headers: { "content-type": "application/json" } });
  check(put, { "put 204": (r) => r.status === 204 });
  const got = http.get(__ENV.BASE + "/get?key=" + encodeURIComponent(key));
  check(got, { "get body": (r) => r.status === 200 && r.body === body });
}
`;

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function round(n: number): string {
  return (Math.round(n * 100) / 100).toFixed(2);
}

async function main() {
  const outPath = process.argv[2];
  const root = await mkdtemp(path.join(tmpdir(), "blaksoc-load-"));
  const scriptPath = path.join(root, "hosting.k6.js");
  await writeFile(scriptPath, K6);
  const store = new FileArchiveStore(path.join(root, "objects"));
  let storedBytes = 0;
  let puts = 0;
  const server = createServer(async (req, res) => {
    try {
      await route(req, res);
    } catch (err) {
      res.writeHead(400, { "content-type": "text/plain" });
      res.end(err instanceof Error ? err.message : "error");
    }
  });

  async function route(req: IncomingMessage, res: ServerResponse) {
    if (req.method === "POST" && req.url === "/put") {
      const payload = JSON.parse(await readBody(req)) as { region: string; key: string; body: string };
      await store.put(payload.region, payload.key, payload.body);
      storedBytes += Buffer.byteLength(payload.body);
      puts += 1;
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method === "GET" && req.url?.startsWith("/get?")) {
      const key = new URL(req.url, "http://127.0.0.1").searchParams.get("key");
      if (!key) throw new Error("archive key");
      const body = await store.get("ap-southeast-2", key);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(body);
      return;
    }
    res.writeHead(404);
    res.end();
  }

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("load server did not bind");
  const base = `http://127.0.0.1:${address.port}`;

  let rejectedNonAu = false;
  try {
    await store.put("us-east-1", "syslog/load/no.log", "no");
  } catch (err) {
    rejectedNonAu = err instanceof Error && /Australia/.test(err.message);
  }
  if (!rejectedNonAu) throw new Error("non-AU put was accepted");

  const version = await command("k6", ["version"]);
  const profiles = [];
  for (const tenants of TENANTS) {
    const lines = tenants * LINES_PER_TENANT;
    storedBytes = 0;
    puts = 0;
    const summaryPath = path.join(root, `summary-${tenants}.json`);
    const cpu0 = process.cpuUsage();
    const started = performance.now();
    const exit = await command("k6", ["run", "--quiet", "--summary-export", summaryPath, "-e", `BASE=${base}`, "-e", `LINES=${lines}`, scriptPath], true);
    const wallMs = round(performance.now() - started);
    const cpu = process.cpuUsage(cpu0);
    if (exit.code !== 0) throw new Error(`k6 exited ${exit.code} for ${tenants} tenants\n${exit.stderr}`);
    const summary = JSON.parse(await readFile(summaryPath, "utf8")) as {
      metrics: Record<string, { avg?: number; "p(95)"?: number; count?: number; value?: number; fails?: number }>;
    };
    const duration = summary.metrics.http_req_duration;
    const failed = summary.metrics.http_req_failed;
    const checks = summary.metrics.checks;
    if (!duration || failed?.value !== 0 || checks?.fails !== 0) throw new Error(`k6 summary failed for ${tenants} tenants`);
    profiles.push({
      tenants,
      objects: puts,
      bytes: storedBytes,
      wallMs,
      httpAvgMs: round(duration.avg ?? 0),
      httpP95Ms: round(duration["p(95)"] ?? 0),
      httpReqs: summary.metrics.http_reqs?.count ?? 0,
      serverRssBytes: process.memoryUsage().rss,
      serverCpuUserUs: cpu.user,
      serverCpuSystemUs: cpu.system,
    });
    if (puts !== lines) throw new Error(`expected ${lines} objects, stored ${puts}`);
  }

  const report = {
    tool: "k6",
    k6Version: version.stdout.trim(),
    host: { platform: platform(), arch: arch(), node: process.version, cpuModel: cpus()[0]?.model ?? "", cpuCount: cpus().length, totalMemBytes: totalmem() },
    linesPerTenant: LINES_PER_TENANT,
    rejectedNonAu: true,
    profiles,
  };
  const json = JSON.stringify(report, null, 2);
  if (outPath) await writeFile(outPath, json + "\n");
  else process.stdout.write(json + "\n");
  server.close();
  await rm(root, { recursive: true, force: true });
}

function command(cmd: string, args: string[], capture = false): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
      if (!capture) process.stderr.write(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
