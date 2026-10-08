import http from "node:http";
import type { AddressInfo } from "node:net";

/** One stored object, with the encryption headers it was written with. `body` holds raw bytes as latin1, so dumps round-trip. */
export type StubObject = { body: string; sse: string | null; kmsKeyId: string | null };

export type S3Stub = {
  endpoint: string;
  /** `${bucket}/${key}` → object. Pass the same map to a new stub to simulate a server restart. */
  objects: Map<string, StubObject>;
  requests: { method: string; bucket: string; key: string; region: string | null }[];
  close(): Promise<void>;
};

const XML = { "content-type": "application/xml" };

function xmlEscape(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function error(res: http.ServerResponse, status: number, code: string, method: string) {
  res.writeHead(status, XML);
  // HEAD responses carry no body; the SDK maps the status alone.
  res.end(method === "HEAD" ? undefined : `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${code}</Message></Error>`);
}

/**
 * Path-style S3 stand-in: PutObject, GetObject, HeadObject, HeadBucket and ListObjectsV2.
 * `buckets` maps bucket name → the region HeadBucket reports. Requests must be SigV4 signed.
 */
export async function startS3Stub(opts: { buckets: Record<string, string>; objects?: Map<string, StubObject>; pageSize?: number }): Promise<S3Stub> {
  const objects = opts.objects ?? new Map<string, StubObject>();
  const requests: S3Stub["requests"] = [];
  const pageSize = opts.pageSize ?? 1000;

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "http://stub");
      const [, bucket = "", ...rest] = url.pathname.split("/");
      const key = rest.map(decodeURIComponent).join("/");
      const method = req.method ?? "GET";
      const auth = req.headers.authorization ?? "";
      const region = /^AWS4-HMAC-SHA256 Credential=[^/]+\/\d{8}\/([^/]+)\/s3\//.exec(auth)?.[1] ?? null;
      requests.push({ method, bucket, key, region });
      if (!auth.startsWith("AWS4-HMAC-SHA256")) return error(res, 403, "AccessDenied", method);
      if (!(bucket in opts.buckets)) return error(res, 404, "NoSuchBucket", method);

      if (!key && method === "GET" && url.searchParams.has("location")) {
        // As AWS: us-east-1 is an empty constraint.
        const constraint = opts.buckets[bucket] === "us-east-1" ? "" : opts.buckets[bucket]!;
        res.writeHead(200, { "content-type": "application/xml" });
        return res.end(`<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">${constraint}</LocationConstraint>`);
      }
      if (!key && method === "HEAD") {
        res.writeHead(200, { "x-amz-bucket-region": opts.buckets[bucket]! });
        return res.end();
      }
      if (!key && method === "GET" && url.searchParams.get("list-type") === "2") {
        const prefix = url.searchParams.get("prefix") ?? "";
        const start = Number(url.searchParams.get("continuation-token") ?? "0");
        const all = [...objects.keys()]
          .filter((k) => k.startsWith(`${bucket}/`))
          .map((k) => k.slice(bucket.length + 1))
          .filter((k) => k.startsWith(prefix))
          .sort();
        const page = all.slice(start, start + pageSize);
        const truncated = start + pageSize < all.length;
        res.writeHead(200, XML);
        return res.end(
          `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
            `<Name>${xmlEscape(bucket)}</Name><Prefix>${xmlEscape(prefix)}</Prefix><KeyCount>${page.length}</KeyCount><MaxKeys>${pageSize}</MaxKeys>` +
            `<IsTruncated>${truncated}</IsTruncated>` +
            page.map((k) => `<Contents><Key>${xmlEscape(k)}</Key><Size>${Buffer.byteLength(objects.get(`${bucket}/${k}`)!.body, "latin1")}</Size></Contents>`).join("") +
            (truncated ? `<NextContinuationToken>${start + pageSize}</NextContinuationToken>` : "") +
            `</ListBucketResult>`,
        );
      }
      if (!key) return error(res, 400, "InvalidRequest", method);

      const id = `${bucket}/${key}`;
      if (method === "PUT") {
        const sse = (req.headers["x-amz-server-side-encryption"] as string | undefined) ?? null;
        const kmsKeyId = (req.headers["x-amz-server-side-encryption-aws-kms-key-id"] as string | undefined) ?? null;
        objects.set(id, { body: Buffer.concat(chunks).toString("latin1"), sse, kmsKeyId });
        res.writeHead(200, { etag: '"stub"', ...(sse ? { "x-amz-server-side-encryption": sse } : {}) });
        return res.end();
      }
      if (method === "DELETE") {
        objects.delete(id);
        res.writeHead(204);
        return res.end();
      }
      const obj = objects.get(id);
      if (!obj) return error(res, 404, "NoSuchKey", method);
      if (method === "HEAD") {
        res.writeHead(200, { "content-length": Buffer.byteLength(obj.body, "latin1") });
        return res.end();
      }
      if (method === "GET") {
        res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
        return res.end(obj.body, "latin1");
      }
      return error(res, 405, "MethodNotAllowed", method);
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    endpoint: `http://127.0.0.1:${port}`,
    objects,
    requests,
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
        // The store keeps connections alive; drop them so close resolves.
        server.closeAllConnections();
      }),
  };
}
