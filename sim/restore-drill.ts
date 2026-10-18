// Restore drill: download + decrypt everything from an obsyncd (normally one
// started on a restored backup) into memory, then compare byte-for-byte with a
// local vault folder. Reads token + derived key from the vault's plugin data.json;
// neither is printed.
//   npx tsx ../sim/restore-drill.ts <serverUrl> <vaultDir>
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { Api, fetchTransport } from "../plugin/src/core/api";
import { Keyring } from "../plugin/src/core/crypto";
import { SyncEngine } from "../plugin/src/core/engine";
import { MemoryState, MemoryVault } from "../plugin/src/core/memory";
import { bytesEqual, fromB64, isExcluded, normPath } from "../plugin/src/core/util";

const [url, dir] = process.argv.slice(2);
const cfg = JSON.parse(readFileSync(join(dir, ".obsidian/plugins/aizu-sync/data.json"), "utf8"));
const api = new Api(url, cfg.token, fetchTransport);
const keys = await Keyring.fromMaster(fromB64(cfg.master));
const vault = new MemoryVault();
const engine = new SyncEngine({ api, keys, vault, state: new MemoryState(), device: "restore-drill", configDir: ".obsidian", guard: async () => false });
await engine.init();
for (let i = 0; i < 3; i++) await engine.sync();

const local = new Map<string, Uint8Array>();
const walk = (d: string) => {
  for (const n of readdirSync(d)) {
    const p = join(d, n), rel = normPath(relative(dir, p));
    if (statSync(p).isDirectory()) { if (!isExcluded(rel + "/x", ".obsidian")) walk(p); }
    else if (!isExcluded(rel, ".obsidian")) local.set(rel, readFileSync(p));
  }
};
walk(dir);

const restored = new Set((await vault.list()).map((s) => s.path));
let same = 0;
const diff: string[] = [], missing: string[] = [], extra: string[] = [];
for (const [p, data] of local) {
  const r = await vault.read(p);
  if (!r) missing.push(p);
  else if (bytesEqual(r, data)) same++;
  else diff.push(p);
}
for (const p of restored) if (!local.has(p)) extra.push(p);
console.log(`local files: ${local.size}  restored: ${restored.size}  identical: ${same}  differ: ${diff.length}  missing: ${missing.length}  extra: ${extra.length}`);
for (const p of [...diff, ...missing, ...extra].slice(0, 10)) console.log("  ", p);
process.exit(diff.length + missing.length + extra.length ? 1 : 0);
