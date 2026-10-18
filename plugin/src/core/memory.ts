// In-memory VaultAdapter and StateStore for tests and the simulator.

import type { Entry, LocalStat, StateStore, VaultAdapter } from "./engine";
import { bytesEqual, normPath, utf8, utf8d } from "./util";

export class MemoryVault implements VaultAdapter {
  files = new Map<string, { data: Uint8Array; mtime: number }>();
  /** Called for user renames only (like Obsidian's rename event). */
  onRename?: (from: string, to: string) => void;
  trash: { path: string; data: Uint8Array }[] = [];
  private clock = 1_000_000;

  private tick() {
    return (this.clock += 1000);
  }

  // Direct "user" edits, used by tests and the simulator.
  put(path: string, text: string) {
    this.files.set(normPath(path), { data: utf8.encode(text), mtime: this.tick() });
  }
  text(path: string): string | undefined {
    const f = this.files.get(normPath(path));
    return f ? utf8d.decode(f.data) : undefined;
  }
  del(path: string) {
    const f = this.files.get(normPath(path));
    if (f) this.trash.push({ path, data: f.data });
    this.files.delete(normPath(path));
  }
  mv(from: string, to: string): boolean {
    if (!this.move(from, to)) return false;
    this.onRename?.(from, to);
    return true;
  }
  private move(from: string, to: string): boolean {
    const f = this.files.get(normPath(from));
    if (!f || this.files.has(normPath(to))) return false;
    this.files.delete(normPath(from));
    this.files.set(normPath(to), f);
    return true;
  }
  snapshot(): Record<string, string> {
    return Object.fromEntries([...this.files].sort(([a], [b]) => (a < b ? -1 : 1)).map(([p, f]) => [p, utf8d.decode(f.data)]));
  }

  async list(): Promise<LocalStat[]> {
    return [...this.files].map(([path, f]) => ({ path, mtime: f.mtime, size: f.data.length }));
  }
  async read(path: string) {
    return this.files.get(normPath(path))?.data ?? null;
  }
  async create(path: string, data: Uint8Array) {
    if (this.files.has(normPath(path))) return false;
    this.files.set(normPath(path), { data, mtime: this.tick() });
    return true;
  }
  async modify(path: string, fn: (cur: Uint8Array) => Uint8Array | null) {
    const f = this.files.get(normPath(path));
    if (!f) return null;
    const next = fn(f.data);
    if (!next) return null;
    this.files.set(normPath(path), { data: next, mtime: this.tick() });
    return next;
  }
  async remove(path: string, expect: Uint8Array) {
    const f = this.files.get(normPath(path));
    if (!f || !bytesEqual(f.data, expect)) return false;
    this.del(path);
    return true;
  }
  async rename(from: string, to: string) {
    return this.move(from, to);
  }
}

export class MemoryState implements StateStore {
  saved: Entry[] = [];
  async load() {
    return this.saved.map((e) => ({ ...e }));
  }
  async save(entries: Entry[]) {
    this.saved = entries.map((e) => ({ ...e }));
  }
}
