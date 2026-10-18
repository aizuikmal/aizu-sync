// A VaultAdapter over a real folder, for profiling the engine against disk I/O.
// Not used by the plugin. Deletes move into <root>/.trash-sim.
import { mkdir, readFile, readdir, rename, stat, writeFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import type { LocalStat, VaultAdapter } from "../plugin/src/core/engine";
import { bytesEqual, normPath } from "../plugin/src/core/util";

export class FsVault implements VaultAdapter {
  reads = 0;
  constructor(private root: string) {}

  async list(): Promise<LocalStat[]> {
    const out: LocalStat[] = [];
    const walk = async (d: string) => {
      for (const ent of await readdir(d, { withFileTypes: true })) {
        const p = join(d, ent.name);
        if (ent.isDirectory()) {
          if (ent.name !== ".trash-sim") await walk(p);
        } else {
          const s = await stat(p);
          out.push({ path: normPath(relative(this.root, p)), mtime: Math.floor(s.mtimeMs), size: s.size });
        }
      }
    };
    await walk(this.root);
    return out;
  }
  async read(path: string) {
    this.reads++;
    try {
      return new Uint8Array(await readFile(join(this.root, path)));
    } catch {
      return null;
    }
  }
  async create(path: string, data: Uint8Array) {
    const p = join(this.root, path);
    await mkdir(dirname(p), { recursive: true });
    try {
      await writeFile(p, data, { flag: "wx" });
      return true;
    } catch {
      return false;
    }
  }
  async modify(path: string, fn: (cur: Uint8Array) => Uint8Array | null) {
    const cur = await this.read(path);
    if (!cur) return null;
    const next = fn(cur);
    if (!next) return null;
    await writeFile(join(this.root, path), next);
    return next;
  }
  async remove(path: string, expect: Uint8Array) {
    const cur = await this.read(path);
    if (!cur || !bytesEqual(cur, expect)) return false;
    const to = join(this.root, ".trash-sim", path);
    await mkdir(dirname(to), { recursive: true });
    await rename(join(this.root, path), to);
    return true;
  }
  async rename(from: string, to: string) {
    const t = join(this.root, to);
    try {
      await stat(t);
      return false;
    } catch {
      /* free */
    }
    await mkdir(dirname(t), { recursive: true });
    try {
      await rename(join(this.root, from), t);
      return true;
    } catch {
      return false;
    }
  }
}
