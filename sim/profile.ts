// Time engine cycles against real folders: device A uploads a copy of a vault,
// device B downloads it, then both idle-sync and sync one edit. Reports wall
// time and file reads per cycle. Needs a throwaway obsyncd (harness startServer).
//   npx tsx ../sim/profile.ts <sourceVaultDir>
import { appendFile, cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Api, fetchTransport } from "../plugin/src/core/api";
import { Keyring } from "../plugin/src/core/crypto";
import { SyncEngine } from "../plugin/src/core/engine";
import { MemoryState } from "../plugin/src/core/memory";
import { startServer } from "../plugin/test/harness";
import { FsVault } from "./fsvault";

const src = process.argv[2];
const srv = await startServer(1000);
const work = await mkdtemp(join(tmpdir(), "aizu-profile-"));
const dirA = join(work, "A"), dirB = join(work, "B");
await cp(src, dirA, { recursive: true, filter: (p) => !p.includes("/.obsidian") });
await mkdir(dirB);

async function device(name: string, dir: string) {
  const api = new Api(srv.url, srv.addDevice(name), fetchTransport);
  const v = await api.vault();
  const keys = await Keyring.fromMaster(await Keyring.deriveMaster("profile", v.kdf_salt, v.kdf_iters));
  const vault = new FsVault(dir);
  const engine = new SyncEngine({ api, keys, vault, state: new MemoryState(), device: name, configDir: ".obsidian", guard: async () => true });
  await engine.init();
  return { vault, engine };
}
async function timed(label: string, d: { vault: FsVault; engine: SyncEngine }) {
  d.vault.reads = 0;
  const t = performance.now();
  const r = await d.engine.sync();
  console.log(`${label.padEnd(34)} ${(performance.now() - t).toFixed(0).padStart(6)} ms  reads ${String(d.vault.reads).padStart(5)}  pushed ${r.pushed} downloaded ${r.downloaded}`);
}

try {
  const A = await device("A", dirA);
  await timed("A: first upload", A);
  await timed("A: idle cycle", A);
  await timed("A: idle cycle", A);
  const B = await device("B", dirB);
  await timed("B: first download (empty folder)", B);
  await timed("B: idle cycle", B);
  await timed("B: idle cycle", B);
  await appendFile(join(dirA, "_profile-edit.md"), `edit ${Date.now()}\n`);
  await timed("A: one new file", A);
  await timed("B: pull that file", B);
  await timed("B: idle cycle", B);
} finally {
  await srv.stop();
  await rm(work, { recursive: true, force: true });
}
