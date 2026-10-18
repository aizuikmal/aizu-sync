// Act as another device: download the vault into memory, delete N files under a
// prefix, push. Used to trigger the mass-delete guard on a real device.
// Key from the vault's data.json; device token from $SIM_TOKEN (never printed).
//   SIM_TOKEN=... npx tsx ../sim/remote-delete.ts <vaultDir> <pathPrefix> <count>
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Api, fetchTransport } from "../plugin/src/core/api";
import { Keyring } from "../plugin/src/core/crypto";
import { SyncEngine } from "../plugin/src/core/engine";
import { MemoryState, MemoryVault } from "../plugin/src/core/memory";
import { fromB64 } from "../plugin/src/core/util";

const [dir, prefix, n] = process.argv.slice(2);
const cfg = JSON.parse(readFileSync(join(dir, ".obsidian/plugins/aizu-sync/data.json"), "utf8"));
const api = new Api(cfg.serverUrl, process.env.SIM_TOKEN!, fetchTransport);
const vault = new MemoryVault();
const engine = new SyncEngine({
  api, keys: await Keyring.fromMaster(fromB64(cfg.master)), vault, state: new MemoryState(),
  device: "sim", configDir: ".obsidian", guard: async () => true, maxDeletes: 1000,
});
await engine.init();
await engine.sync();
const victims = (await vault.list()).map((s) => s.path).filter((p) => p.startsWith(prefix)).sort().slice(0, Number(n));
for (const p of victims) vault.del(p);
const r = await engine.sync();
console.log(`downloaded ${(await vault.list()).length + victims.length} files, deleted ${victims.length}: ${victims[0]} .. ${victims.at(-1)}`, r);
