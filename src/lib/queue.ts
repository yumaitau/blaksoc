import { Queue, type JobsOptions } from "bullmq";
import { withJobMeta } from "./obs/context";
import { redisConnectionOptions } from "./redis";

export const QUEUES = {
  ingest: "ingest", // poll providers for alerts
  sync: "sync", // assets, vulns, health
  playbook: "playbook", // trigger evaluation + step execution
  response: "response", // approved response actions
  intel: "intel", // CVE/KEV/EPSS refresh, advisories, sightings
  detection: "detection", // scheduled Sigma deployments
  report: "report",
  notify: "notify",
  surface: "surface", // attested external scans
} as const;

export type QueueName = (typeof QUEUES)[keyof typeof QUEUES];

/** Every enqueue carries the caller's request id and trace context, so one id follows web → worker. */
class CorrelatedQueue extends Queue {
  override add(name: string, data: unknown, opts?: JobsOptions) {
    return super.add(name, withJobMeta(data), opts);
  }
}

const g = globalThis as unknown as { __blaksocQueues?: Map<string, Queue> };

export function queue(name: QueueName): Queue {
  g.__blaksocQueues ??= new Map();
  let q = g.__blaksocQueues.get(name);
  if (!q) {
    q = new CorrelatedQueue(name, { connection: redisConnectionOptions(), defaultJobOptions: { attempts: 3, backoff: { type: "exponential", delay: 5000 }, removeOnComplete: 1000, removeOnFail: 5000 } });
    g.__blaksocQueues.set(name, q);
  }
  return q;
}
