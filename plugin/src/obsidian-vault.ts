// VaultAdapter over Obsidian's Vault API. Text writes go through vault.process,
// which is atomic with an open editor, so a merge never races the user's typing.

import { App, normalizePath, TFile, requestUrl } from "obsidian";
import type { LocalStat, VaultAdapter, StateStore, Entry } from "./core/engine";
import { ApiError, type Transport } from "./core/api";
import { bytesEqual, isMergeable, utf8, utf8d } from "./core/util";

const buf = (u: Uint8Array): ArrayBuffer => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

export class ObsidianVault implements VaultAdapter {
  constructor(private app: App) {}

  private file(path: string): TFile | null {
    return this.app.vault.getFileByPath(normalizePath(path));
  }

  private async ensureParent(path: string) {
    const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
    if (!dir || this.app.vault.getAbstractFileByPath(dir)) return;
    let acc = "";
    for (const part of dir.split("/")) {
      acc = acc ? `${acc}/${part}` : part;
      if (!this.app.vault.getAbstractFileByPath(acc)) await this.app.vault.createFolder(acc).catch(() => undefined);
    }
  }

  async list(): Promise<LocalStat[]> {
    return this.app.vault.getFiles().map((f) => ({ path: f.path, mtime: f.stat.mtime, size: f.stat.size }));
  }

  async read(path: string) {
    const f = this.file(path);
    return f ? new Uint8Array(await this.app.vault.readBinary(f)) : null;
  }

  async create(path: string, data: Uint8Array) {
    const p = normalizePath(path);
    if (this.app.vault.getAbstractFileByPath(p) || (await this.app.vault.adapter.exists(p))) return false;
    await this.ensureParent(p);
    await this.app.vault.createBinary(p, buf(data));
    return true;
  }

  async modify(path: string, fn: (cur: Uint8Array) => Uint8Array | null) {
    const f = this.file(path);
    if (!f) return null;
    if (isMergeable(path)) {
      let out: Uint8Array | null = null;
      await this.app.vault.process(f, (text) => {
        out = fn(utf8.encode(text));
        return out ? utf8d.decode(out) : text;
      });
      return out;
    }
    const cur = new Uint8Array(await this.app.vault.readBinary(f));
    const next = fn(cur);
    if (!next) return null;
    await this.app.vault.modifyBinary(f, buf(next));
    return next;
  }

  async remove(path: string, expect: Uint8Array) {
    const f = this.file(path);
    if (!f) return false;
    if (!bytesEqual(new Uint8Array(await this.app.vault.readBinary(f)), expect)) return false;
    await this.app.fileManager.trashFile(f); // honours the user's trash setting
    return true;
  }

  async rename(from: string, to: string) {
    const f = this.file(from);
    const t = normalizePath(to);
    if (!f || this.app.vault.getAbstractFileByPath(t)) return false;
    // A case-only rename is the same path on APFS; anything else that exists is taken.
    if (f.path.toLowerCase() !== t.toLowerCase() && (await this.app.vault.adapter.exists(t))) return false;
    await this.ensureParent(t);
    await this.app.vault.rename(f, t); // not fileManager.renameFile: link updates sync as their own edits
    return true;
  }
}

/** Local base state in IndexedDB, one database per vault. */
export class IdbState implements StateStore {
  constructor(private name: string) {}

  private open(): Promise<IDBDatabase> {
    return new Promise((ok, fail) => {
      const req = indexedDB.open(this.name, 1);
      req.onupgradeneeded = () => req.result.createObjectStore("kv");
      req.onsuccess = () => ok(req.result);
      req.onerror = () => fail(req.error);
    });
  }

  async load(): Promise<Entry[]> {
    const db = await this.open();
    try {
      return await new Promise((ok, fail) => {
        const r = db.transaction("kv").objectStore("kv").get("entries");
        r.onsuccess = () => ok((r.result as Entry[]) ?? []);
        r.onerror = () => fail(r.error);
      });
    } finally {
      db.close();
    }
  }

  async save(entries: Entry[]): Promise<void> {
    const db = await this.open();
    try {
      await new Promise<void>((ok, fail) => {
        const tx = db.transaction("kv", "readwrite");
        tx.objectStore("kv").put(entries, "entries");
        tx.oncomplete = () => ok();
        tx.onerror = () => fail(tx.error);
      });
    } finally {
      db.close();
    }
  }
}

/** requestUrl bypasses CORS, which matters on iOS. */
export const obsidianTransport: Transport = async (req) => {
  const body = req.body instanceof Uint8Array ? buf(req.body) : req.body;
  let r;
  try {
    r = await requestUrl({ url: req.url, method: req.method, headers: req.headers, body, throw: false });
  } catch (e) {
    throw new ApiError(0, `network: ${e}`); // offline, VPN down, server down
  }
  const bytes = new Uint8Array(r.arrayBuffer);
  return { status: r.status, bytes: () => bytes, text: () => utf8d.decode(bytes) };
};
