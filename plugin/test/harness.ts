// Spins up a real obsyncd on a random port and makes in-memory clients for it.

import { execFileSync, spawn, ChildProcess } from "node:child_process";
import { mkdtempSync, existsSync, statSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { Api, fetchTransport } from "../src/core/api";
import { Keyring } from "../src/core/crypto";
import { SyncEngine, EngineOptions } from "../src/core/engine";
import { MemoryState, MemoryVault } from "../src/core/memory";

const SERVER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../server");
const BIN = join(SERVER_DIR, ".bin", "obsyncd");

function newestMtime(dir: string): number {
  return Math.max(...readdirSync(dir).filter((f) => f.endsWith(".go")).map((f) => statSync(join(dir, f)).mtimeMs));
}

export function buildServer(): string {
  if (!existsSync(BIN) || statSync(BIN).mtimeMs < newestMtime(SERVER_DIR)) {
    execFileSync("go", ["build", "-o", BIN, "."], { cwd: SERVER_DIR, stdio: "inherit" });
  }
  return BIN;
}

async function freePort(): Promise<number> {
  return new Promise((ok) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => ok(p));
    });
  });
}

export interface TestServer {
  url: string;
  dataDir: string;
  addDevice(name: string): string;
  stop(): Promise<void>;
  restart(): Promise<void>;
  bin: string;
}

export const PASSPHRASE = "correct horse battery staple";

/** A fresh obsyncd whose vault passphrase is already set by the admin, as in production. */
export async function startServer(iters = 1000, passphrase: string | null = PASSPHRASE): Promise<TestServer> {
  const bin = buildServer();
  const dataDir = mkdtempSync(join(tmpdir(), "obsync-test-"));
  execFileSync(bin, ["-data", dataDir, "init", "-iters", String(iters)]);
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  let proc: ChildProcess;
  const launch = async () => {
    proc = spawn(bin, ["-data", dataDir, "serve", "-listen", `127.0.0.1:${port}`], { stdio: "ignore" });
    for (let i = 0; i < 100; i++) {
      try {
        if ((await fetch(url + "/healthz")).ok) return;
      } catch {}
      await new Promise((r) => setTimeout(r, 30));
    }
    throw new Error("obsyncd did not start");
  };
  await launch();
  const addDevice = (name: string) => execFileSync(bin, ["-data", dataDir, "device", "add", "-max", "1000", name]).toString().trim();
  if (passphrase !== null) {
    // as in production: the admin sets the passphrase check on the server
    const v = await new Api(url, addDevice("admin"), fetchTransport).vault();
    const keys = await Keyring.fromMaster(await Keyring.deriveMaster(passphrase, v.kdf_salt, v.kdf_iters));
    execFileSync(bin, ["-data", dataDir, "set-key-check"], { input: await keys.makeKeyCheck() });
  }
  const stop = () =>
    new Promise<void>((ok) => {
      if (proc.exitCode !== null || proc.signalCode !== null) return ok();
      proc.once("exit", () => ok());
      proc.kill("SIGKILL");
    });
  return {
    url,
    dataDir,
    bin,
    addDevice,
    stop,
    restart: async () => {
      await stop();
      await launch();
    },
  };
}

export interface Client {
  name: string;
  vault: MemoryVault;
  state: MemoryState;
  engine: SyncEngine;
  conflicts: [string, string][];
  rebuild(): Promise<void>;
}

export async function makeClient(srv: TestServer, name: string, passphrase = PASSPHRASE, opts: Partial<EngineOptions> = {}): Promise<Client> {
  const token = srv.addDevice(name);
  const api = new Api(srv.url, token, fetchTransport);
  const v = await api.vault();
  const keys = await Keyring.fromMaster(await Keyring.deriveMaster(passphrase, v.kdf_salt, v.kdf_iters));
  const c: Client = {
    name,
    vault: new MemoryVault(),
    state: new MemoryState(),
    conflicts: [],
    engine: undefined as unknown as SyncEngine,
    async rebuild() {
      // a fresh engine over the same vault + saved state (an app restart)
      this.engine = new SyncEngine({
        api,
        keys,
        vault: this.vault,
        state: this.state,
        device: name,
        guard: async () => true,
        onConflict: (p, copy) => this.conflicts.push([p, copy]),
        ...opts,
      });
      this.vault.onRename = (f, t) => this.engine.noteRename(f, t);
      await this.engine.init();
    },
  };
  await c.rebuild();
  return c;
}

/** Sync all clients round-robin until a full pass changes nothing. */
export async function settle(clients: Client[], maxRounds = 12): Promise<void> {
  let last: string[] = [];
  for (let i = 0; i < maxRounds; i++) {
    let busy = false;
    last = [];
    for (const c of clients) {
      const r = await c.engine.sync();
      last.push(`${c.name}: ${JSON.stringify(r)} files=${JSON.stringify(Object.keys(c.vault.snapshot()))}`);
      if (r.again || r.pushed || r.downloaded || r.deleted || r.merged || r.conflicts) busy = true;
    }
    if (!busy) return;
  }
  throw new Error("did not settle\n" + last.join("\n"));
}
