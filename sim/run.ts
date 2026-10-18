// Randomized 3-device simulator against a real obsyncd.
//
//   plugin/node_modules/.bin/tsx sim/run.ts [--from 1] [--to 200] [--steps 80]
//
// Each seed: fresh server, three in-memory devices, random edits / creates /
// deletes / renames / binary edits / syncs, syncs racing user edits, state
// wipes, app restarts and server kill -9s. Then everyone settles and we check:
//   1. convergence: all three vaults are byte-for-byte identical
//   2. no loss: every line a user wrote and nobody deliberately removed is
//      still in the vault (conflict copies count)
//   3. the server's own verify passes and every device agrees with the server

import { execFileSync } from "node:child_process";
import { Client, makeClient, settle, startServer, TestServer } from "../plugin/test/harness";

const arg = (k: string, d: number) => {
  const i = process.argv.indexOf(`--${k}`);
  return i > 0 ? Number(process.argv[i + 1]) : d;
};

function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const NAMES = ["Inbox.md", "Daily/2026-10-18.md", "Daily/2026-10-19.md", "Projects/Plan.md", "Projects/Ideas.md", "Untitled.md", "People/Ali.md", "img.png", "scan.pdf"];
const TOKEN = /\bt\d+x\d+\b/g;

let traceOf: (t: string) => string = () => "";

async function runSeed(seed: number, steps: number): Promise<string | null> {
  const r = rng(seed);
  const pick = <T>(xs: T[]) => xs[Math.floor(r() * xs.length)];
  const srv: TestServer = await startServer();
  const log: string[] = [];
  const inserted = new Set<string>();
  const deleted = new Set<string>();
  let n = 0;
  const born = new Map<string, string>();
  let cur = "";
  const tok = () => {
    const t = `t${seed}x${n++}`;
    born.set(t, cur);
    return t;
  };
  try {
    const cs: Client[] = [];
    for (const name of ["mac-a", "mac-b", "iphone"]) cs.push(await makeClient(srv, name));

    const files = (c: Client) => Object.keys(c.vault.snapshot());
    const forget = (text: string) => text.match(TOKEN)?.forEach((t) => deleted.add(t));

    const userOp = (c: Client) => {
      cur = `step ${log.length} by ${c.name}`;
      const fs = files(c);
      const x = r();
      if (x < 0.45 && fs.length) {
        const f = pick(fs);
        const old = c.vault.text(f)!;
        if (!f.endsWith(".md")) {
          forget(old);
          const t = tok();
          inserted.add(t);
          c.vault.put(f, `BIN ${t}`);
          log.push(`${c.name} binedit ${f}`);
          return;
        }
        const lines = old.split("\n");
        const y = r();
        const i = Math.floor(r() * (lines.length + 1));
        if (y < 0.5) {
          const t = tok();
          inserted.add(t);
          lines.splice(i, 0, `- ${t} note`);
          log.push(`${c.name} insert ${f}@${i}`);
        } else if (y < 0.7 && lines.length > 1) {
          const j = Math.min(i, lines.length - 1);
          forget(lines[j]);
          lines.splice(j, 1);
          log.push(`${c.name} dropline ${f}@${j}`);
        } else if (y < 0.9 && lines.length > 1) {
          const j = Math.min(i, lines.length - 1);
          forget(lines[j]);
          const t = tok();
          inserted.add(t);
          lines[j] = `- ${t} rewritten`;
          log.push(`${c.name} rewrite ${f}@${j}`);
        } else {
          const t = tok();
          inserted.add(t);
          lines.push(`- ${t} appended`);
          log.push(`${c.name} append ${f}`);
        }
        c.vault.put(f, lines.join("\n"));
      } else if (x < 0.62) {
        const f = pick(NAMES);
        if (c.vault.text(f) !== undefined) return;
        const t = tok();
        inserted.add(t);
        c.vault.put(f, f.endsWith(".md") ? `# ${f}\n\n- ${t} first\n` : `BIN ${t}`);
        log.push(`${c.name} create ${f}`);
      } else if (x < 0.72 && fs.length) {
        const f = pick(fs);
        forget(c.vault.text(f)!);
        c.vault.del(f);
        log.push(`${c.name} delete ${f}`);
      } else if (fs.length) {
        const f = pick(fs);
        const ext = f.slice(f.lastIndexOf("."));
        const to = pick(NAMES.filter((x) => x.endsWith(ext))).replace(/(\.\w+)$/, ` ${Math.floor(r() * 3)}$1`);
        if (c.vault.mv(f, to)) log.push(`${c.name} rename ${f} -> ${to}`);
      }
    };

    const safeSync = async (c: Client) => {
      try {
        await c.engine.sync();
      } catch (e) {
        log.push(`${c.name} sync failed: ${String(e).slice(0, 80)}`);
      }
    };

    const where = (t: string) =>
      cs
        .map((c) => `${c.name}:[${Object.entries(c.vault.snapshot()).filter(([, txt]) => new RegExp(`\\b${t}\\b`).test(txt)).map(([f]) => f).join("|")}]`)
        .join(" ");
    const timeline: string[][] = []; // per step, per token location; filled lazily on failure via snapshots
    const snaps: { step: number; label: string; vaults: Record<string, string>[] }[] = [];
    const shot = (label: string) => snaps.push({ step: log.length, label, vaults: cs.map((c) => c.vault.snapshot()) });
    traceOf = (t: string) => {
      const re = new RegExp(`\\b${t}\\b`);
      let prev = "";
      const out: string[] = [];
      for (const sn of snaps) {
        const loc = sn.vaults.map((v, i) => `${cs[i].name}:[${Object.entries(v).filter(([, txt]) => re.test(txt)).map(([f]) => f).join("|")}]`).join(" ");
        if (loc !== prev) out.push(`    after op ${sn.step - 1} (${sn.label}): ${loc}`);
        prev = loc;
      }
      return out.join("\n");
    };
    void where;
    void timeline;

    for (let s = 0; s < steps; s++) {
      shot(log[log.length - 1] ?? "start");
      const c = pick(cs);
      const x = r();
      if (x < 0.55) userOp(c);
      else if (x < 0.82) {
        log.push(`${c.name} sync`);
        await safeSync(c);
        log.push(`${c.name} sync done`);
      } else if (x < 0.92) {
        // a sync racing the user: edits land between the engine's awaits
        log.push(`${c.name} sync+race`);
        const p = safeSync(c);
        for (let k = 0; k < 1 + Math.floor(r() * 3); k++) {
          await new Promise((res) => setTimeout(res, Math.floor(r() * 4)));
          userOp(c);
        }
        await p;
      } else if (x < 0.95) {
        log.push(`${c.name} wipe-state`);
        await c.engine.resetState();
        await c.rebuild();
      } else if (x < 0.98) {
        log.push(`${c.name} restart-app`);
        await c.rebuild();
      } else {
        log.push(`server kill -9 during ${c.name} sync`);
        const p = safeSync(c);
        await new Promise((res) => setTimeout(res, Math.floor(r() * 5)));
        await srv.restart();
        await p;
      }
    }

    shot("end of steps");
    await settle(cs, 20);
    shot("settled");

    const snap = cs[0].vault.snapshot();
    for (const c of cs.slice(1)) {
      if (JSON.stringify(c.vault.snapshot()) !== JSON.stringify(snap)) return fail("vaults diverged", cs);
    }
    const all = Object.values(snap).join("\n");
    const lost = [...inserted].filter((t) => !deleted.has(t) && !new RegExp(`\\b${t}\\b`).test(all));
    if (lost.length) {
      const inHistory = await historyHas(cs[0], lost);
      return fail(`lost tokens ${lost.map((t) => `${t} (born ${born.get(t)}; in server history: ${inHistory.get(t) ?? "no"})\n  timeline:\n${traceOf(t)}`).join(", ")}`, cs);
    }
    for (const c of cs) {
      const v = await c.engine.verify();
      if (v.differ.length || v.localOnly.length || v.remoteOnly.length) return fail(`${c.name} disagrees with server ${JSON.stringify(v)}`, cs);
    }
    try {
      execFileSync(srv.bin, ["-data", srv.dataDir, "verify"], { stdio: "pipe" });
    } catch (e) {
      return fail(`server verify failed: ${(e as { stdout?: Buffer }).stdout}`, cs);
    }
    return null;
  } catch (e) {
    return `seed ${seed}: exception ${String((e as Error).stack ?? e)}\n  last ops:\n  ${log.slice(-25).join("\n  ")}`;
  } finally {
    await srv.stop();
  }

  function fail(why: string, cs: Client[]) {
    return `seed ${seed}: ${why}\n  ops:\n  ${log.map((l, i) => `${i}: ${l}`).join("\n  ")}\n  vault: ${JSON.stringify(cs[0].vault.snapshot(), null, 1)}`;
  }
}

/** Which lost tokens still exist somewhere in server history (any version of any file)? */
async function historyHas(c: Client, toks: string[]): Promise<Map<string, string>> {
  const eng = c.engine as unknown as { o: { api: import("../plugin/src/core/api").Api; keys: import("../plugin/src/core/crypto").Keyring } };
  const { api, keys } = eng.o;
  const out = new Map<string, string>();
  const st = await api.state(true);
  for (const f of st.files) {
    for (const v of (await api.history(f.file_id)).versions) {
      if (!v.blob_sha) continue;
      const text = new TextDecoder().decode(await keys.decBlob(await api.blob(v.blob_sha), v.file_id));
      const path = await keys.decPath(v.enc_path, v.file_id);
      for (const t of toks) if (text.includes(t) && !out.has(t)) out.set(t, `v${v.version} ${path} dev${v.device_id}${v.deleted ? " (tombstone)" : ""}`);
    }
  }
  return out;
}

const from = arg("from", 1), to = arg("to", 50), steps = arg("steps", 80);
const t0 = Date.now();
let failed = 0;
for (let seed = from; seed <= to; seed++) {
  const res = await runSeed(seed, steps);
  if (res) {
    failed++;
    console.log("FAIL " + res + "\n");
  }
}
console.log(`seeds ${from}-${to}, ${steps} steps each: ${to - from + 1 - failed} ok, ${failed} failed, ${((Date.now() - t0) / 1000).toFixed(1)}s`);
process.exit(failed ? 1 : 0);
