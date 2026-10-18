// The sync engine. Each cycle: pull remote changes, scan the vault, classify
// every file against its last-synced base, apply remote changes locally, push
// local ones. Rules that keep data safe:
//   - Local writes are compare-and-swap (modify/remove check current content).
//   - A copy is created before anything is overwritten.
//   - Edits beat deletes. The first sync of a device never deletes.
//   - Local state is a cache: losing it costs a re-scan, never a file.
//   - Mass deletes/overwrites pause and ask (guard).

import { Api, ApiError, CommitItem, CommitResult, FileMeta } from "./api";
import { Keyring, sha256Hex } from "./crypto";
import { merge3 } from "./merge";
import { bytesEqual, conflictName, isExcluded, isMergeable, isSafeRemotePath, Mutex, normPath, toB64, utf8, utf8d, uuid4 } from "./util";

export interface LocalStat {
  path: string;
  mtime: number;
  size: number;
}

export interface VaultAdapter {
  list(): Promise<LocalStat[]>;
  read(path: string): Promise<Uint8Array | null>;
  /** false if the path already exists. Creates parent folders. */
  create(path: string, data: Uint8Array): Promise<boolean>;
  /** Atomic read-modify-write; fn returns null to decline. Returns what was written, or null. */
  modify(path: string, fn: (cur: Uint8Array) => Uint8Array | null): Promise<Uint8Array | null>;
  /** Moves to trash only if the content still equals expect. */
  remove(path: string, expect: Uint8Array): Promise<boolean>;
  /** false if from is missing or to exists. Creates parent folders. */
  rename(from: string, to: string): Promise<boolean>;
}

export interface Entry {
  fileId: string;
  path: string;
  version: number;
  tag: string;
  blob: string;
  mtime: number; // -1 = re-hash on next scan
  size: number;
}

export interface StateStore {
  load(): Promise<Entry[]>;
  save(entries: Entry[]): Promise<void>;
}

export interface GuardSummary {
  localDeletes: string[];
  remoteDeletes: string[];
  overwrites: string[];
  total: number;
}

export type Status = "idle" | "syncing" | "offline" | "paused" | "error";

export interface EngineOptions {
  api: Api;
  keys: Keyring;
  vault: VaultAdapter;
  state: StateStore;
  device: string;
  configDir?: string;
  now?: () => Date;
  /** Asked before a cycle with many deletes/overwrites. false = pause. */
  guard?: (s: GuardSummary) => Promise<boolean>;
  onStatus?: (s: Status, detail?: string) => void;
  onConflict?: (path: string, copy: string) => void;
  log?: (msg: string) => void;
  maxDeletes?: number;
  maxFileSize?: number;
}

export class WrongPassphraseError extends Error {}
export class VaultNotReadyError extends Error {}
export class IntegrityError extends Error {}
export class GuardPausedError extends Error {}

interface Remote {
  meta: FileMeta;
  path: string;
}

interface Local extends LocalStat {
  tag: string;
  bytes?: Uint8Array;
}

interface Push {
  kind: "edit" | "create" | "rename" | "resurrect" | "delete";
  fileId: string;
  base: number;
  path: string;
  bytes?: Uint8Array;
  tag?: string;
  blob?: string;
  size: number;
  mtime: number;
  localMtime: number;
}

export interface CycleReport {
  again: boolean;
  why?: string[];
  pulled: number;
  pushed: number;
  downloaded: number;
  deleted: number;
  merged: number;
  conflicts: number;
}

export class SyncEngine {
  private entries = new Map<string, Entry>(); // by fileId
  private remote = new Map<string, Remote>(); // by fileId
  private cursor = 0;
  private loaded = false;
  private dirty = false;
  private mutex = new Mutex();
  private renames = new Map<string, string>(); // NFC new path -> NFC path it had at last sync
  private o: Required<Omit<EngineOptions, "guard" | "onStatus" | "onConflict" | "log">> & EngineOptions;
  paused = false;

  constructor(opts: EngineOptions) {
    this.o = { configDir: ".obsidian", now: () => new Date(), maxDeletes: 10, maxFileSize: 50 << 20, ...opts };
  }

  private log(m: string) {
    this.o.log?.(m);
  }

  /** Checks the passphrase against the vault before anything else can happen. */
  async init(): Promise<void> {
    const v = await this.o.api.vault();
    // The passphrase is fixed by the admin on the server (sim/set-passphrase.ts),
    // never by whichever device happens to connect first.
    if (!v.key_check) throw new VaultNotReadyError("this vault has no passphrase set up on the server");
    if (!(await this.o.keys.verifyKeyCheck(v.key_check))) throw new WrongPassphraseError("passphrase does not match this vault");
    for (const e of await this.o.state.load()) this.entries.set(e.fileId, e);
  }

  /** Hint from the vault's rename event, so a rename + edit before the next sync
   *  stays one file instead of a delete + create. Optional: content matching
   *  catches plain renames without it. */
  noteRename(from: string, to: string) {
    const f = normPath(from), t = normPath(to);
    const orig = this.renames.get(f) ?? f;
    this.renames.delete(f);
    if (orig !== t) this.renames.set(t, orig);
  }

  /** Forget the local base state (e.g. IndexedDB wiped). Safe by design. */
  async resetState(): Promise<void> {
    this.entries.clear();
    this.loaded = false;
    await this.o.state.save([]);
  }

  sync(): Promise<CycleReport> {
    return this.mutex.run(async () => {
      this.o.onStatus?.("syncing");
      const total: CycleReport = { again: false, pulled: 0, pushed: 0, downloaded: 0, deleted: 0, merged: 0, conflicts: 0 };
      try {
        for (let i = 0; i < 6; i++) {
          total.pulled += await this.pull();
          const r = await this.cycle();
          for (const k of ["pushed", "downloaded", "deleted", "merged", "conflicts"] as const) total[k] += r[k];
          total.again = r.again;
          total.why = r.why;
          if (!r.again) break;
        }
        await this.persist();
        this.o.onStatus?.(this.paused ? "paused" : "idle");
        return total;
      } catch (e) {
        await this.persist().catch(() => undefined);
        if (e instanceof GuardPausedError) this.o.onStatus?.("paused", e.message);
        else if (e instanceof ApiError || e instanceof TypeError) this.o.onStatus?.("offline", String(e));
        else this.o.onStatus?.("error", String(e));
        throw e;
      }
    });
  }

  private async persist() {
    if (!this.dirty) return;
    await this.o.state.save([...this.entries.values()]);
    this.dirty = false;
  }

  private setEntry(e: Entry) {
    this.entries.set(e.fileId, e);
    this.dirty = true;
  }

  private dropEntry(fileId: string) {
    if (this.entries.delete(fileId)) this.dirty = true;
  }

  // ---- pull ----

  private async pull(): Promise<number> {
    if (!this.loaded) {
      const st = await this.o.api.state(true);
      const fresh = new Map<string, Remote>();
      for (const m of st.files) {
        const r = await this.remoteOf(m);
        if (this.safe(r)) fresh.set(m.file_id, r);
      }
      this.remote = fresh;
      this.cursor = Math.max(st.head, ...st.files.map((f) => f.version), 0);
      this.loaded = true;
      let maxEntry = 0;
      for (const e of this.entries.values()) maxEntry = Math.max(maxEntry, e.version);
      if (maxEntry > this.cursor) this.log(`server head ${this.cursor} is behind local base ${maxEntry}: server was restored from a backup; local copies win`);
      return st.files.length;
    }
    let n = 0;
    for (;;) {
      const r = await this.o.api.changes(this.cursor);
      for (const m of r.changes) {
        const rm = await this.remoteOf(m);
        if (this.safe(rm)) this.remote.set(m.file_id, rm);
        else this.remote.delete(m.file_id);
        this.cursor = Math.max(this.cursor, m.version);
        n++;
      }
      if (!r.more) return n;
    }
  }

  /** Never materialise a remote path outside the synced area (e.g. into .obsidian/plugins). */
  private safe(r: Remote): boolean {
    if (isSafeRemotePath(r.path, this.o.configDir)) return true;
    this.log(`ignoring remote file with an unsafe path: ${JSON.stringify(r.path)}`);
    return false;
  }

  private async remoteOf(m: FileMeta): Promise<Remote> {
    const prev = this.remote.get(m.file_id);
    if (prev && prev.meta.enc_path === m.enc_path) return { meta: m, path: prev.path };
    // Throws on a wrong key or tampering: we never act on data we can't authenticate.
    return { meta: m, path: await this.o.keys.decPath(m.enc_path, m.file_id) };
  }

  // ---- one cycle ----

  private async cycle(): Promise<CycleReport> {
    const rep: CycleReport = { again: false, why: [], pulled: 0, pushed: 0, downloaded: 0, deleted: 0, merged: 0, conflicts: 0 };
    const again = (why: string) => {
      rep.again = true;
      rep.why!.push(why);
    };
    const v = this.o.vault;
    const local = await this.scan();
    // Bytes read after classification must still be the content we classified,
    // or a compare-and-swap would "expect" an edit the user made mid-cycle.
    const bytesOf = async (l: Local) => {
      if (l.bytes) return l.bytes;
      const b = await v.read(l.path);
      if (b && (await this.o.keys.tag(b)) === l.tag) return (l.bytes = b);
      again(`changed under us: ${l.path}`);
      return undefined;
    };

    const claimed = new Set<string>();
    const pushes: Push[] = [];
    const localDeletes: { e: Entry; l: Local }[] = [];
    const applies: { e: Entry; r: Remote; l: Local }[] = [];
    const merges: { e: Entry; r: Remote; l: Local }[] = [];
    const missing: Entry[] = [];

    for (let e of [...this.entries.values()]) {
      const r = this.remote.get(e.fileId);
      if (!r) {
        this.dropEntry(e.fileId); // unknown to the server: the local file is re-reconciled as untracked
        continue;
      }
      if (r.meta.version < e.version) {
        // Server restored from an older backup. Our base is a descendant of what it
        // has, so rebase onto it: any local content that differs is newer and pushes.
        e = { ...e, version: r.meta.version, tag: r.meta.content_tag, blob: r.meta.blob_sha, mtime: -1 };
        this.setEntry(e);
      }
      const l = local.get(normPath(e.path));
      if (l) claimed.add(normPath(e.path));
      const remoteChanged = r.meta.version !== e.version;
      if (!l) {
        if (remoteChanged) this.dropEntry(e.fileId); // remote edit beats local delete: re-downloaded below
        else missing.push(e);
        continue;
      }
      const localChanged = l.tag !== e.tag;
      if (!localChanged && !remoteChanged) {
        // Content is the base; remember its stat so the next scan skips re-hashing it
        // (downloads store mtime -1 and would otherwise be re-read every cycle).
        if (e.mtime !== l.mtime || e.size !== l.size) this.setEntry((e = { ...e, mtime: l.mtime, size: l.size }));
        if (normPath(r.path) !== normPath(e.path)) {
          pushes.push(this.pushOf("rename", e.fileId, e.version, l, e.path, { tag: e.tag, blob: e.blob }));
        }
      } else if (!localChanged) {
        if (r.meta.deleted) localDeletes.push({ e, l });
        else applies.push({ e, r, l });
      } else if (!remoteChanged) {
        pushes.push(this.pushOf("edit", e.fileId, e.version, l, e.path));
      } else if (r.meta.deleted) {
        pushes.push(this.pushOf("resurrect", e.fileId, r.meta.version, l, e.path));
      } else if (r.meta.content_tag === l.tag) {
        applies.push({ e, r, l }); // both sides made the same change
      } else {
        merges.push({ e, r, l });
      }
    }

    // Local renames: a tracked file vanished and an untracked one with the same content appeared.
    const untracked = [...local.values()].filter((l) => !claimed.has(normPath(l.path)));
    const byTag = new Map<string, Local[]>();
    for (const u of untracked) byTag.set(u.tag, [...(byTag.get(u.tag) ?? []), u]);
    const remoteDeletes: Entry[] = [];
    const hinted = new Map<string, Local>();
    for (const u of untracked) {
      const from = this.renames.get(normPath(u.path));
      if (from) hinted.set(from, u);
    }
    for (const k of [...this.renames.keys()]) if (!local.has(k) || claimed.has(k)) this.renames.delete(k);
    for (const e of missing) {
      const h = hinted.get(normPath(e.path));
      if (h && !claimed.has(normPath(h.path))) {
        claimed.add(normPath(h.path));
        this.renames.delete(normPath(h.path));
        byTag.set(h.tag, (byTag.get(h.tag) ?? []).filter((x) => x !== h));
        pushes.push(h.tag === e.tag ? this.pushOf("rename", e.fileId, e.version, h, h.path, { tag: e.tag, blob: e.blob }) : this.pushOf("edit", e.fileId, e.version, h, h.path));
        continue;
      }
      let u = byTag.get(e.tag)?.shift();
      while (u && claimed.has(normPath(u.path))) u = byTag.get(e.tag)?.shift();
      if (u) {
        claimed.add(normPath(u.path));
        pushes.push(this.pushOf("rename", e.fileId, e.version, u, u.path, { tag: e.tag, blob: e.blob }));
      } else {
        remoteDeletes.push(e);
      }
    }
    for (const e of remoteDeletes) {
      pushes.push({ kind: "delete", fileId: e.fileId, base: e.version, path: e.path, size: 0, mtime: Math.floor(Date.now() / 1000), localMtime: 0 });
    }

    // Untracked local files vs remote files at the same path.
    const tracked = new Set(this.entries.keys());
    const liveByPath = new Map<string, Remote>();
    for (const r of this.remote.values()) if (!r.meta.deleted) liveByPath.set(normPath(r.path), r);
    const collisions: { u: Local; r: Remote }[] = [];
    const adopts: { u: Local; r: Remote }[] = [];
    for (const u of untracked) {
      if (claimed.has(normPath(u.path))) continue;
      const r = liveByPath.get(normPath(u.path));
      if (!r) {
        pushes.push(this.pushOf("create", uuid4(), 0, u, u.path));
      } else if (tracked.has(r.meta.file_id)) {
        again(`remote file moving onto ${u.path}`); // that remote file is moving here; settle it first
      } else if (r.meta.content_tag === u.tag) {
        adopts.push({ u, r });
      } else {
        collisions.push({ u, r });
      }
      claimed.add(normPath(u.path));
    }

    // Remote files nobody tracks and no local file occupies: download.
    const downloads: Remote[] = [];
    const trackedNow = new Set(this.entries.keys());
    for (const r of this.remote.values()) {
      if (r.meta.deleted || trackedNow.has(r.meta.file_id)) continue;
      if (adopts.some((a) => a.r === r) || collisions.some((c) => c.r === r)) continue;
      if (claimed.has(normPath(r.path))) {
        again(`download blocked by local file at ${r.path}`); // a local file still sits there; it moves or goes this cycle
        continue;
      }
      downloads.push(r);
    }

    // Guard: ask before anything sweeping.
    const overwrites = [...applies.filter((a) => a.r.meta.content_tag !== a.e.tag).map((a) => a.e.path), ...collisions.map((c) => c.u.path)];
    const g: GuardSummary = {
      localDeletes: localDeletes.map((d) => d.e.path),
      remoteDeletes: remoteDeletes.map((e) => e.path),
      overwrites,
      total: local.size,
    };
    const maxOver = Math.max(20, Math.floor(local.size * 0.2));
    if (g.localDeletes.length > this.o.maxDeletes || g.remoteDeletes.length > this.o.maxDeletes || overwrites.length > maxOver) {
      const ok = this.o.guard ? await this.o.guard(g) : false;
      if (!ok) {
        this.paused = true;
        throw new GuardPausedError(`paused: ${g.localDeletes.length} local deletes, ${g.remoteDeletes.length} remote deletes, ${overwrites.length} overwrites`);
      }
    }
    this.paused = false;

    // Fetch every blob this cycle needs in one go.
    const need: string[] = [];
    for (const a of applies) if (a.r.meta.content_tag !== a.l.tag) need.push(a.r.meta.blob_sha);
    for (const m of merges) need.push(m.r.meta.blob_sha, m.e.blob);
    for (const c of collisions) need.push(c.r.meta.blob_sha);
    for (const d of downloads) need.push(d.meta.blob_sha);
    const blobs = need.length ? await this.o.api.blobs(need) : new Map<string, Uint8Array>();
    // Decrypt and check the plaintext against the content tag it was committed with,
    // so the server cannot hand us a different (e.g. older) blob for this version.
    const plain = async (sha: string, fileId: string, tag: string) => {
      const p = await this.o.keys.decBlob(blobs.get(sha)!, fileId);
      if ((await this.o.keys.tag(p)) !== tag) throw new IntegrityError(`blob ${sha.slice(0, 12)} does not match its content tag`);
      return p;
    };

    // 1. Remote deletes of untouched files.
    for (const { e, l } of localDeletes) {
      const b = await bytesOf(l);
      if (b && (await v.remove(l.path, b))) {
        this.dropEntry(e.fileId);
        rep.deleted++;
      } else again(`delete skipped ${l.path}`);
    }

    // 2. Remote edits/renames of untouched files.
    for (const { e, r, l } of applies) {
      let path = l.path;
      if (r.meta.content_tag !== l.tag) {
        const lb = await bytesOf(l);
        const nb = await plain(r.meta.blob_sha, r.meta.file_id, r.meta.content_tag);
        const w = lb ? await v.modify(path, (cur) => (bytesEqual(cur, lb) ? nb : null)) : null;
        if (!w) {
          again(`overwrite skipped ${path}`);
          continue;
        }
        rep.downloaded++;
      }
      path = await this.moveTo(path, r.path);
      this.setEntry(this.entryOf(r, path));
    }

    // 3. Both sides edited: merge, or keep a conflict copy.
    for (const { e, r, l } of merges) {
      const lb = await bytesOf(l);
      if (!lb) {
        again(`merge: no local bytes ${l.path}`);
        continue;
      }
      const rb = await plain(r.meta.blob_sha, r.meta.file_id, r.meta.content_tag);
      const bb = await plain(e.blob, e.fileId, e.tag);
      let written: Uint8Array | null = null;
      if (isMergeable(l.path)) {
        const base = utf8d.decode(bb), remote = utf8d.decode(rb);
        written = await v.modify(l.path, (cur) => {
          const m = merge3(base, utf8d.decode(cur), remote);
          return m.ok ? utf8.encode(m.text) : null;
        });
      }
      if (written) {
        rep.merged++;
        const path = await this.moveTo(l.path, r.path);
        this.setEntry(this.entryOf(r, path, -1)); // rebased onto remote; our merged edit pushes next cycle
        again(`merged ${path}`);
        continue;
      }
      // Unmergeable: remote keeps the name, local content survives as a copy (created first).
      const copy = await this.freeName(l.path);
      if (!(await v.create(copy, lb))) {
        again(`conflict copy failed ${copy}`);
        continue;
      }
      const w = await v.modify(l.path, (cur) => (bytesEqual(cur, lb) ? rb : null));
      if (!w) {
        again(`conflict overwrite skipped ${l.path}`); // user kept typing; the copy holds lb, next cycle re-merges
        continue;
      }
      rep.conflicts++;
      this.o.onConflict?.(l.path, copy);
      const path = await this.moveTo(l.path, r.path);
      this.setEntry(this.entryOf(r, path));
      again(`new conflict copy ${copy}`); // the copy is a new local file
    }

    // 4. First-sync / offline-create collisions.
    for (const { u, r } of adopts) this.setEntry(this.entryOf(r, u.path, u.mtime, u.size));
    for (const { u, r } of collisions) {
      const copy = await this.freeName(u.path);
      if (!(await v.rename(u.path, copy))) {
        again(`collision rename failed ${u.path}`);
        continue;
      }
      const rb = await plain(r.meta.blob_sha, r.meta.file_id, r.meta.content_tag);
      if (await v.create(u.path, rb)) {
        this.setEntry(this.entryOf(r, u.path));
        rep.conflicts++;
        this.o.onConflict?.(u.path, copy);
      }
      again(`collision ${u.path}`);
    }

    // 5. New remote files.
    for (const r of downloads) {
      const rb = await plain(r.meta.blob_sha, r.meta.file_id, r.meta.content_tag);
      if (await v.create(r.path, rb)) {
        this.setEntry(this.entryOf(r, r.path));
        rep.downloaded++;
      } else again(`download create failed ${r.path}`);
    }

    // 6. Push. A local rename onto a path another remote file already owns would be
    //    refused forever (path_exists) while that file can't download into the
    //    occupied path: step aside to a conflict name instead.
    for (const p of pushes) {
      if (p.kind === "delete" || p.kind === "create") continue;
      const owner = liveByPath.get(normPath(p.path));
      if (!owner || owner.meta.file_id === p.fileId) continue;
      const alt = await this.freeName(p.path);
      if (await v.rename(p.path, alt)) {
        this.o.onConflict?.(p.path, alt);
        p.path = alt;
        rep.conflicts++;
      }
    }
    if (pushes.length) {
      for (const p of pushes) if (p.kind !== "delete" && p.kind !== "rename" && !p.bytes) p.bytes = (await v.read(p.path)) ?? undefined;
      const ready = pushes.filter((p) => p.kind === "delete" || p.kind === "rename" || p.bytes);
      if (ready.length < pushes.length) again("push: unreadable files");
      const ok = await this.push(ready);
      rep.pushed += ok;
      if (ok < ready.length) again(`push: ${ready.length - ok} rejected`);
    }
    return rep;
  }

  private async scan(): Promise<Map<string, Local>> {
    const byPath = new Map<string, Entry>();
    for (const e of this.entries.values()) byPath.set(normPath(e.path), e);
    const out = new Map<string, Local>();
    for (const s of await this.o.vault.list()) {
      if (isExcluded(s.path, this.o.configDir) || s.size > this.o.maxFileSize) continue;
      const e = byPath.get(normPath(s.path));
      if (e && e.mtime >= 0 && e.mtime === s.mtime && e.size === s.size) {
        out.set(normPath(s.path), { ...s, tag: e.tag });
        continue;
      }
      const bytes = await this.o.vault.read(s.path);
      if (!bytes) continue;
      out.set(normPath(s.path), { ...s, size: bytes.length, tag: await this.o.keys.tag(bytes), bytes });
    }
    return out;
  }

  private pushOf(kind: Push["kind"], fileId: string, base: number, l: Local, path: string, same?: { tag: string; blob: string }): Push {
    return { kind, fileId, base, path, bytes: same ? undefined : l.bytes, tag: same?.tag ?? l.tag, blob: same?.blob, size: l.size, mtime: Math.floor(l.mtime / 1000), localMtime: l.mtime };
  }

  private entryOf(r: Remote, path: string, mtime = -1, size = r.meta.size): Entry {
    return { fileId: r.meta.file_id, path, version: r.meta.version, tag: r.meta.content_tag, blob: r.meta.blob_sha, mtime, size };
  }

  /** Renames a local file to the remote's path; if that name is taken, to a conflict name. */
  private async moveTo(from: string, to: string): Promise<string> {
    if (normPath(from) === normPath(to)) return from;
    if (await this.o.vault.rename(from, to)) return to;
    const alt = await this.freeName(to);
    return (await this.o.vault.rename(from, alt)) ? alt : from;
  }

  private async freeName(path: string): Promise<string> {
    const taken = new Set((await this.o.vault.list()).map((s) => normPath(s.path)));
    for (let n = 0; ; n++) {
      const c = conflictName(path, this.o.device, this.o.now(), n);
      if (!taken.has(normPath(c))) return c;
    }
  }

  private async push(pushes: Push[]): Promise<number> {
    const k = this.o.keys;
    let ok = 0;
    let batch: { p: Push; item: CommitItem }[] = [];
    let bytes = 0;
    const flush = async () => {
      if (!batch.length) return;
      const res = await this.o.api.commit(batch.map((b) => b.item));
      res.results.forEach((r, i) => {
        if (this.applyResult(batch[i].p, batch[i].item, r)) ok++;
      });
      batch = [];
      bytes = 0;
    };
    for (const p of pushes) {
      const item: CommitItem = {
        file_id: p.fileId,
        base_version: p.base,
        path_hmac: await k.pathHmac(p.path),
        enc_path: await k.encPath(p.path, p.fileId),
        content_tag: "",
        blob_sha: "",
        size: p.size,
        deleted: p.kind === "delete",
        mtime: p.mtime,
      };
      if (p.kind === "rename") {
        item.content_tag = p.tag!;
        item.blob_sha = p.blob!;
      } else if (p.kind !== "delete") {
        const blob = await k.encBlob(p.bytes!, p.fileId);
        item.content_tag = await k.tag(p.bytes!);
        item.blob_sha = await sha256Hex(blob);
        item.size = p.bytes!.length;
        item.blob = toB64(blob);
        bytes += item.blob.length;
      }
      batch.push({ p, item });
      if (batch.length >= 100 || bytes > 8 << 20) await flush();
    }
    await flush();
    return ok;
  }

  private applyResult(p: Push, item: CommitItem, r: CommitResult): boolean {
    if (!r.ok) {
      if (r.error === "bad_request") this.log(`server rejected ${p.path}: ${r.detail}`);
      return false;
    }
    if (p.kind === "delete") {
      this.dropEntry(p.fileId);
      return true;
    }
    // Keep the remote map in step so the next cycle doesn't see our own commit as foreign.
    const meta: FileMeta = { ...item, version: r.version!, device_id: 0, deleted: false };
    delete (meta as Partial<CommitItem>).blob;
    this.remote.set(p.fileId, { meta, path: p.path });
    this.setEntry({ fileId: p.fileId, path: p.path, version: r.version!, tag: item.content_tag, blob: item.blob_sha, mtime: p.localMtime, size: p.size });
    return true;
  }

  /** For the history view: every version of the file now at `path`, oldest first. */
  async history(path: string): Promise<{ meta: FileMeta; path: string }[]> {
    const e = [...this.entries.values()].find((x) => normPath(x.path) === normPath(path));
    return e ? this.historyOf(e.fileId) : [];
  }

  async historyOf(fileId: string): Promise<{ meta: FileMeta; path: string }[]> {
    const h = await this.o.api.history(fileId);
    return Promise.all(h.versions.map(async (m) => ({ meta: m, path: await this.o.keys.decPath(m.enc_path, m.file_id) })));
  }

  async versionContent(m: FileMeta): Promise<Uint8Array> {
    return this.o.keys.decBlob(await this.o.api.blob(m.blob_sha), m.file_id);
  }

  /** Deleted files whose last version is a tombstone, for "Restore deleted files". */
  deletedFiles(): { meta: FileMeta; path: string }[] {
    return [...this.remote.values()].filter((r) => r.meta.deleted);
  }

  /** Compare local tags with the server's current tags. */
  async verify(): Promise<{ ok: number; differ: string[]; localOnly: string[]; remoteOnly: string[] }> {
    return this.mutex.run(async () => {
      await this.pull();
      const local = await this.scan();
      const out = { ok: 0, differ: [] as string[], localOnly: [] as string[], remoteOnly: [] as string[] };
      const seen = new Set<string>();
      for (const r of this.remote.values()) {
        if (r.meta.deleted) continue;
        const l = local.get(normPath(r.path));
        seen.add(normPath(r.path));
        if (!l) out.remoteOnly.push(r.path);
        else if (l.tag === r.meta.content_tag) out.ok++;
        else out.differ.push(r.path);
      }
      for (const [p, l] of local) if (!seen.has(p)) out.localOnly.push(l.path);
      return out;
    });
  }

  get head() {
    return this.cursor;
  }
}
