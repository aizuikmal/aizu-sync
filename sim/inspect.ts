// Read-only view of what the server holds, decrypted with a vault's own key
// (token + derived key from its plugin data.json; neither is printed).
//   npx tsx ../sim/inspect.ts <vaultDir> summary
//   npx tsx ../sim/inspect.ts <vaultDir> find <path-substring>      paths, versions, deleted flag
//   npx tsx ../sim/inspect.ts <vaultDir> show <path> [--content]    every version of one file
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Api, fetchTransport, type FileMeta } from "../plugin/src/core/api";
import { Keyring } from "../plugin/src/core/crypto";
import { fromB64, utf8d } from "../plugin/src/core/util";

const [dir, cmd, arg, flag] = process.argv.slice(2);
const cfg = JSON.parse(readFileSync(join(dir, ".obsidian/plugins/aizu-sync/data.json"), "utf8"));
const api = new Api(cfg.serverUrl, cfg.token, fetchTransport);
const keys = await Keyring.fromMaster(fromB64(cfg.master));
const when = (ts?: number) => (ts ? new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) : "-");

const { head, files } = await api.state(true);
const named = await Promise.all(files.map(async (f) => ({ f, path: await keys.decPath(f.enc_path, f.file_id) })));

if (cmd === "summary") {
  const live = named.filter((n) => !n.f.deleted).length;
  console.log(`head ${head}  live ${live}  deleted ${named.length - live}`);
} else if (cmd === "find") {
  for (const { f, path } of named.filter((n) => n.path.includes(arg)).sort((a, b) => (a.path < b.path ? -1 : 1)))
    console.log(`${f.deleted ? "DELETED" : "live   "} v${f.version}  ${f.size}B  ${path}  (${f.file_id.slice(0, 8)})`);
} else if (cmd === "show") {
  const hits = named.filter((n) => n.path === arg);
  if (!hits.length) console.log("no such path on server (live or deleted)");
  for (const { f } of hits) {
    const { versions } = await api.history(f.file_id);
    for (const v of versions as FileMeta[]) {
      const p = await keys.decPath(v.enc_path, v.file_id);
      let line = `v${v.version}  ${when(v.ts)}  dev ${v.device_id}  ${v.deleted ? "DELETED" : `${v.size}B`}  ${p}`;
      if (flag === "--content" && !v.deleted) line += "\n    | " + utf8d.decode(await keys.decBlob(await api.blob(v.blob_sha), v.file_id)).replace(/\n/g, "\n    | ");
      console.log(line);
    }
  }
}
