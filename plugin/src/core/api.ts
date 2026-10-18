// HTTP client for obsyncd. The transport is injected: Obsidian's requestUrl in
// the plugin (no CORS on iOS), fetch in tests and the simulator.

import { fromB64 } from "./util";

export interface HttpRequest {
  method: "GET" | "POST" | "PUT";
  url: string;
  headers: Record<string, string>;
  body?: string | Uint8Array;
}
export interface HttpResponse {
  status: number;
  text(): string;
  bytes(): Uint8Array;
}
export type Transport = (req: HttpRequest) => Promise<HttpResponse>;

export interface FileMeta {
  file_id: string;
  version: number;
  path_hmac: string;
  enc_path: string;
  content_tag: string;
  blob_sha: string;
  size: number;
  deleted: boolean;
  mtime: number;
  device_id: number;
  ts?: number;
}

export interface VaultInfo {
  kdf_salt: string;
  kdf_iters: number;
  key_check: string;
  head: number;
}

export interface CommitItem {
  file_id: string;
  base_version: number;
  path_hmac: string;
  enc_path: string;
  content_tag: string;
  blob_sha: string;
  size: number;
  deleted: boolean;
  mtime: number;
  blob?: string;
}

export interface CommitResult {
  file_id: string;
  ok: boolean;
  version?: number;
  error?: "conflict" | "path_exists" | "missing_blob" | "bad_request";
  detail?: string;
  current?: FileMeta;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    msg: string,
  ) {
    super(msg);
  }
}

export class Api {
  constructor(
    private base: string,
    private token: string,
    private transport: Transport,
  ) {
    this.base = base.replace(/\/+$/, "");
  }

  private async call(method: HttpRequest["method"], path: string, body?: unknown): Promise<HttpResponse> {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}` };
    let b: string | Uint8Array | undefined;
    if (body instanceof Uint8Array) {
      b = body;
      headers["Content-Type"] = "application/octet-stream";
    } else if (body !== undefined) {
      b = JSON.stringify(body);
      headers["Content-Type"] = "application/json";
    }
    const res = await this.transport({ method, url: this.base + path, headers, body: b });
    if (res.status < 200 || res.status >= 300) throw new ApiError(res.status, `${method} ${path}: HTTP ${res.status}`);
    return res;
  }

  private async json<T>(method: HttpRequest["method"], path: string, body?: unknown): Promise<T> {
    return JSON.parse((await this.call(method, path, body)).text()) as T;
  }

  /** Raw authenticated request, for extensions (see ext.ts). */
  async request(method: HttpRequest["method"], path: string, body?: Uint8Array): Promise<Uint8Array> {
    return (await this.call(method, path, body)).bytes();
  }

  vault() {
    return this.json<VaultInfo>("GET", "/v1/vault");
  }

  state(includeDeleted = true) {
    return this.json<{ head: number; files: FileMeta[] }>("GET", `/v1/state${includeDeleted ? "?deleted=1" : ""}`);
  }

  changes(since: number) {
    return this.json<{ changes: FileMeta[]; more: boolean }>("GET", `/v1/changes?since=${since}`);
  }

  history(fileId: string) {
    return this.json<{ versions: FileMeta[] }>("GET", `/v1/history/${fileId}`);
  }

  async blob(sha: string): Promise<Uint8Array> {
    return (await this.call("GET", `/v1/blob/${sha}`)).bytes();
  }

  /** Fetches many blobs, following the server's size-budget paging. */
  async blobs(shas: string[]): Promise<Map<string, Uint8Array>> {
    const out = new Map<string, Uint8Array>();
    let todo = [...new Set(shas)];
    while (todo.length) {
      const r = await this.json<{ blobs: Record<string, string>; missing: string[]; rest: string[] }>("POST", "/v1/blobs", { shas: todo.slice(0, 500) });
      for (const [sha, b64] of Object.entries(r.blobs)) out.set(sha, fromB64(b64));
      if (r.missing.length) throw new ApiError(404, `server is missing blobs: ${r.missing.slice(0, 3).join(", ")}`);
      todo = [...(r.rest ?? []), ...todo.slice(500)];
    }
    return out;
  }

  async putBlob(sha: string, data: Uint8Array): Promise<void> {
    await this.call("PUT", `/v1/blob/${sha}`, data);
  }

  commit(items: CommitItem[]) {
    return this.json<{ results: CommitResult[]; head: number }>("POST", "/v1/commit", { items });
  }

  wsUrl(): string {
    return this.base.replace(/^http/, "ws") + "/v1/ws";
  }
}

/** fetch-based transport, for Node (tests, simulator) and desktop debugging. */
export const fetchTransport: Transport = async (req) => {
  const r = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body as BodyInit | undefined });
  const buf = new Uint8Array(await r.arrayBuffer());
  return { status: r.status, bytes: () => buf, text: () => new TextDecoder().decode(buf) };
};
