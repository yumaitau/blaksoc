import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = path.resolve(import.meta.dirname, "../..");
const chart = path.join(root, "deploy/helm/blaksoc");

function has(cmd: string): boolean {
  try {
    execFileSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const base = ["template", "blaksoc", chart, "-n", "blaksoc", "-f", path.join(chart, "values.yaml")];
const prod = [...base, "-f", path.join(chart, "values-yumait-prod.yaml"), "--set", "image.tag=0123456789ab"];
const render = (args: string[]) => execFileSync("helm", args, { encoding: "utf8" });
const fails = (args: string[]) => () => execFileSync("helm", args, { stdio: "pipe" });

describe("Hermes (in-cluster agent) chart", () => {
  it.skipIf(!has("helm"))("is off by default and renders an hourly, never-retried CronJob in production", () => {
    expect(render(base)).not.toContain("blaksoc-hermes");
    const out = render(prod);
    expect(out).toContain("kind: CronJob");
    expect(out).toContain('schedule: "0 * * * *"');
    expect(out).toContain("ttlSecondsAfterFinished: 86400");
    expect(out).toContain('timeZone: "Australia/Sydney"');
    expect(out).toContain("concurrencyPolicy: Forbid");
    expect(out).toContain("backoffLimit: 0");
    expect(out).toContain("image: 959038055523.dkr.ecr.ap-southeast-2.amazonaws.com/blaksoc-hermes:0123456789ab");
    expect(out).toContain("serviceAccountName: blaksoc-hermes");
    expect(out).toContain('{ name: BLAKSOC_API_URL, value: "http://blaksoc-blaksoc-web.blaksoc.svc:80" }');
    expect(out).toContain('{ name: HERMES_DRY_RUN, value: "false" }'); // production acts (owner, 2026-10-08)
    expect(out).toContain('{ name: HERMES_MODEL, value: "au.anthropic.claude-sonnet-4-5-20250929-v1:0" }');
    expect(out).toContain('{ name: HERMES_BEDROCK_REGION, value: "ap-southeast-2" }');
  }, 60_000);

  it.skipIf(!has("helm"))("mounts only the Hermes token key, no keys, read-only root and its own non-root user", () => {
    const job = render([...prod, "--show-only", "templates/hermes.yaml"]);
    expect(job).toContain("valueFrom: { secretKeyRef: { name: blaksoc-runtime, key: HERMES_BLAKSOC_TOKEN } }");
    expect(job.match(/secretKeyRef/g)).toHaveLength(1);
    expect(job).not.toContain("envFrom");
    expect(job).not.toMatch(/AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/);
    expect(job).toContain("readOnlyRootFilesystem: true");
    expect(job).toContain("runAsUser: 10000");
    expect(job).toContain("automountServiceAccountToken: false");
    // Web and worker never receive the Hermes credential.
    const app = render([...prod, "--show-only", "templates/web.yaml", "--show-only", "templates/worker.yaml"]);
    expect(app).not.toContain("HERMES_BLAKSOC_TOKEN");
  }, 60_000);

  it.skipIf(!has("helm"))("limits Hermes egress to DNS, the web pods, Pod Identity and Bedrock HTTPS", () => {
    const out = render([...prod, "--set", "networkPolicy.enabled=true", "--set", "networkPolicy.egressCidrs={10.0.0.0/16}", "--show-only", "templates/networkpolicy.yaml"]);
    const hermes = out.split("---").find((doc) => doc.includes("name: blaksoc-blaksoc-hermes"))!;
    expect(hermes).toContain("ingress: []");
    expect(hermes).toContain("k8s-app: kube-dns");
    expect(hermes).toContain("app.kubernetes.io/component: web } }");
    expect(hermes).toContain("cidr: 169.254.170.23/32");
    expect(hermes).toContain("ports: [{ protocol: TCP, port: 443 }]");
    expect(hermes).not.toContain("namespaceSelector: {}");
    expect(hermes).not.toContain("10.0.0.0/16");
    const web = out.split("---").find((doc) => doc.includes("name: blaksoc-blaksoc-web"))!;
    expect(web).toContain("app.kubernetes.io/component: hermes } }");
  }, 60_000);

  it.skipIf(!has("helm"))("refuses non-Australian models and regions, raised caps and open Bedrock CIDRs", () => {
    const on = [...base, "--set", "hermes.enabled=true"];
    expect(fails([...on, "--set", "hermes.model.id=us.anthropic.claude-sonnet-4-5-20250929-v1:0"])).toThrow(/Australian/);
    expect(fails([...on, "--set", "hermes.model.id=global.anthropic.claude-sonnet-4-5-20250929-v1:0"])).toThrow(/Australian/);
    expect(fails([...on, "--set", "hermes.model.region=us-west-2"])).toThrow(/ap-southeast-2 or ap-southeast-4/);
    expect(fails([...on, "--set", "hermes.caps.close=11"])).toThrow(/may not exceed 10/);
    expect(fails([...on, "--set", "hermes.caps.noiseRules=6"])).toThrow(/may not exceed 5/);
    expect(fails([...on, "--set", "networkPolicy.enabled=true", "--set", "hermes.networkPolicy.bedrockCidrs={0.0.0.0/0}"])).toThrow(/not the whole Internet/);
    expect(render([...on, "--set", "hermes.model.id=au.anthropic.claude-opus-5-5"])).toContain('value: "au.anthropic.claude-opus-5-5"');
    expect(render([...on, "--set", "hermes.dryRun=false"])).toContain('{ name: HERMES_DRY_RUN, value: "false" }');
  }, 60_000);

  it("keeps chart caps and the controller's hard ceilings in step", async () => {
    const values = await readFile(path.join(chart, "values.yaml"), "utf8");
    const policy = await readFile(path.join(root, "hermes/warden/policy.py"), "utf8");
    expect(values).toContain("caps: { close: 10, noiseRules: 5, purge: 10, annotations: 50 }");
    expect(policy).toContain('HARD_CAPS = {"close": 10, "noise_rule": 5, "purge": 10, "annotate": 50}');
  });
});
