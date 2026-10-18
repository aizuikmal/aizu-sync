import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { GuardPausedError, IntegrityError, VaultNotReadyError, WrongPassphraseError } from "../src/core/engine";
import { Api, fetchTransport } from "../src/core/api";
import { Keyring, sha256Hex } from "../src/core/crypto";
import { toB64, utf8, uuid4 } from "../src/core/util";
import { Client, makeClient, PASSPHRASE, settle, startServer, TestServer } from "./harness";

let srv: TestServer;
beforeEach(async () => {
  srv = await startServer();
});
afterEach(async () => {
  await srv.stop();
});

const same = (...cs: Client[]) => {
  const snap = cs[0].vault.snapshot();
  for (const c of cs.slice(1)) expect(c.vault.snapshot()).toEqual(snap);
  return snap;
};

describe("engine", () => {
  it("uploads from one device and downloads into an empty one", async () => {
    const a = await makeClient(srv, "mac-a");
    a.vault.put("Inbox.md", "hello");
    a.vault.put("Projects/Plan.md", "# plan\n");
    await a.engine.sync();
    const b = await makeClient(srv, "iphone");
    await settle([a, b]);
    expect(same(a, b)).toEqual({ "Inbox.md": "hello", "Projects/Plan.md": "# plan\n" });
  });

  it("propagates edits, renames and deletes", async () => {
    const a = await makeClient(srv, "mac-a");
    const b = await makeClient(srv, "mac-b");
    a.vault.put("n.md", "v1\n");
    a.vault.put("gone.md", "bye\n");
    await settle([a, b]);
    a.vault.put("n.md", "v2\n");
    a.vault.mv("n.md", "Folder/n2.md");
    a.vault.del("gone.md");
    await settle([a, b]);
    expect(same(a, b)).toEqual({ "Folder/n2.md": "v2\n" });
    expect(b.vault.trash.map((t) => t.path)).toEqual(["gone.md"]);
  });

  it("merges concurrent edits on different lines from three devices", async () => {
    const [a, b, c] = [await makeClient(srv, "a"), await makeClient(srv, "b"), await makeClient(srv, "c")];
    a.vault.put("daily.md", "# 2026-10-18\n\nmorning\n\nnoon\n\nevening\n");
    await settle([a, b, c]);
    a.vault.put("daily.md", "# 2026-10-18\n\nmorning: gym\n\nnoon\n\nevening\n");
    b.vault.put("daily.md", "# 2026-10-18\n\nmorning\n\nnoon: lunch w/ client\n\nevening\n");
    c.vault.put("daily.md", "# 2026-10-18\n\nmorning\n\nnoon\n\nevening: read\n");
    await settle([a, b, c]);
    expect(same(a, b, c)["daily.md"]).toBe("# 2026-10-18\n\nmorning: gym\n\nnoon: lunch w/ client\n\nevening: read\n");
    expect(a.conflicts.length + b.conflicts.length + c.conflicts.length).toBe(0);
  });

  it("keeps both sides of a true conflict", async () => {
    const a = await makeClient(srv, "mac");
    const b = await makeClient(srv, "iphone");
    a.vault.put("x.md", "line\n");
    await settle([a, b]);
    a.vault.put("x.md", "line from mac\n");
    b.vault.put("x.md", "line from iphone\n");
    await settle([a, b]);
    const snap = same(a, b);
    const values = Object.values(snap);
    expect(values).toContain("line from mac\n");
    expect(values).toContain("line from iphone\n");
    expect(Object.keys(snap).length).toBe(2);
    expect(Object.keys(snap).some((p) => p.includes("(conflict "))).toBe(true);
  });

  it("an edit beats a concurrent delete", async () => {
    const a = await makeClient(srv, "a");
    const b = await makeClient(srv, "b");
    a.vault.put("keep.md", "v1\n");
    await settle([a, b]);
    a.vault.del("keep.md");
    b.vault.put("keep.md", "v2 important\n");
    await settle([a, b]);
    expect(same(a, b)).toEqual({ "keep.md": "v2 important\n" });
  });

  it("a delete on one side and an untouched copy on the other deletes", async () => {
    const a = await makeClient(srv, "a");
    const b = await makeClient(srv, "b");
    a.vault.put("d.md", "x\n");
    await settle([a, b]);
    b.vault.del("d.md");
    await settle([a, b]);
    expect(same(a, b)).toEqual({});
  });

  it("rename on one device while another edits keeps both changes", async () => {
    const a = await makeClient(srv, "a");
    const b = await makeClient(srv, "b");
    a.vault.put("old.md", "one\ntwo\n");
    await settle([a, b]);
    a.vault.mv("old.md", "new.md");
    b.vault.put("old.md", "one\ntwo\nthree\n");
    await settle([a, b]);
    expect(same(a, b)).toEqual({ "new.md": "one\ntwo\nthree\n" });
  });

  it("offline creates of the same path keep both versions", async () => {
    const a = await makeClient(srv, "a");
    const b = await makeClient(srv, "b");
    a.vault.put("Untitled.md", "from a\n");
    b.vault.put("Untitled.md", "from b\n");
    await settle([a, b]);
    expect(Object.values(same(a, b)).sort()).toEqual(["from a\n", "from b\n"]);
  });

  it("adopts identical files on first sync without duplicates (cutover)", async () => {
    const a = await makeClient(srv, "a");
    for (let i = 0; i < 30; i++) a.vault.put(`n${i}.md`, `note ${i}\n`);
    await a.engine.sync();
    const b = await makeClient(srv, "b");
    for (let i = 0; i < 30; i++) b.vault.put(`n${i}.md`, `note ${i}\n`);
    b.vault.put("only-b.md", "b\n");
    await settle([a, b]);
    const snap = same(a, b);
    expect(Object.keys(snap).length).toBe(31);
    expect(b.conflicts).toEqual([]);
  });

  it("losing local state costs nothing", async () => {
    const a = await makeClient(srv, "a");
    const b = await makeClient(srv, "b");
    for (let i = 0; i < 10; i++) a.vault.put(`n${i}.md`, `${i}\n`);
    await settle([a, b]);
    await b.engine.resetState();
    await b.rebuild();
    await settle([a, b]);
    expect(Object.keys(same(a, b)).length).toBe(10);
    expect(b.conflicts).toEqual([]);
  });

  it("an app restart picks up edits made while closed", async () => {
    const a = await makeClient(srv, "a");
    const b = await makeClient(srv, "b");
    a.vault.put("n.md", "1\n");
    await settle([a, b]);
    a.vault.put("n.md", "1\n2 (edited by Claude Code while Obsidian was closed)\n");
    await a.rebuild();
    await settle([a, b]);
    expect(b.vault.text("n.md")).toContain("edited by Claude Code");
  });

  it("refuses a vault whose passphrase was never set by the admin", async () => {
    const bare = await startServer(1000, null);
    try {
      await expect(makeClient(bare, "first-device", "anything at all")).rejects.toBeInstanceOf(VaultNotReadyError);
      const api = new Api(bare.url, bare.addDevice("check"), fetchTransport);
      expect((await api.vault()).key_check).toBeFalsy(); // the device did not get to define it
      expect((await api.state()).files).toHaveLength(0);
    } finally {
      await bare.stop();
    }
  });

  it("refuses a wrong passphrase before touching anything", async () => {
    const a = await makeClient(srv, "a");
    a.vault.put("n.md", "x");
    await a.engine.sync();
    await expect(makeClient(srv, "evil", "wrong passphrase")).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it("pauses on a mass delete when the guard says no", async () => {
    const a = await makeClient(srv, "a");
    const b = await makeClient(srv, "b", undefined, { guard: async () => false });
    for (let i = 0; i < 25; i++) a.vault.put(`n${i}.md`, `${i}\n`);
    await settle([a, b]);
    for (let i = 0; i < 25; i++) a.vault.del(`n${i}.md`);
    await a.engine.sync().catch(() => undefined); // a has guard=true: deletes go up
    await expect(b.engine.sync()).rejects.toBeInstanceOf(GuardPausedError);
    expect(Object.keys(b.vault.snapshot()).length).toBe(25);
  });

  it("binary conflicts keep both files", async () => {
    const a = await makeClient(srv, "a");
    const b = await makeClient(srv, "b");
    a.vault.put("img.png", "PNG-1");
    await settle([a, b]);
    a.vault.put("img.png", "PNG-A");
    b.vault.put("img.png", "PNG-B");
    await settle([a, b]);
    expect(Object.values(same(a, b)).sort()).toEqual(["PNG-A", "PNG-B"]);
  });

  it("ignores .obsidian, .trash and OS litter", async () => {
    const a = await makeClient(srv, "a");
    const b = await makeClient(srv, "b");
    a.vault.put(".obsidian/plugins/aizu-sync/data.json", '{"token":"secret"}');
    a.vault.put(".DS_Store", "x");
    a.vault.put("real.md", "r");
    await settle([a, b]);
    expect(b.vault.snapshot()).toEqual({ "real.md": "r" });
  });

  it("survives a server crash mid-way and a restore from an older backup", async () => {
    const a = await makeClient(srv, "a");
    const b = await makeClient(srv, "b");
    a.vault.put("one.md", "1\n");
    await settle([a, b]);
    const snap = join(srv.dataDir, "backup.db");
    execFileSync(srv.bin, ["-data", srv.dataDir, "snapshot", snap]);
    a.vault.put("two.md", "2\n");
    a.vault.put("one.md", "1 edited\n");
    await settle([a, b]);
    // restore the older DB (blobs are append-only so they all still exist)
    await srv.stop();
    execFileSync("cp", [snap, join(srv.dataDir, "obsync.db")]);
    execFileSync("rm", ["-f", join(srv.dataDir, "obsync.db-wal"), join(srv.dataDir, "obsync.db-shm")]);
    await srv.restart();
    await a.rebuild();
    await b.rebuild();
    await settle([a, b]);
    const s = same(a, b);
    expect(s["one.md"]).toBe("1 edited\n");
    expect(s["two.md"]).toBe("2\n");
  });

  it("stores no plaintext content or paths on the server", async () => {
    const a = await makeClient(srv, "a");
    a.vault.put("Private/Bank PIN.md", "my pin is 4821");
    await a.engine.sync();
    const all: Buffer[] = [];
    const walk = (d: string) => {
      for (const f of readdirSync(d)) {
        const p = join(d, f);
        if (statSync(p).isDirectory()) walk(p);
        else all.push(readFileSync(p));
      }
    };
    walk(srv.dataDir);
    const blob = Buffer.concat(all).toString("latin1");
    expect(blob).not.toContain("4821");
    expect(blob).not.toContain("Bank PIN");
    expect(blob).not.toContain("Private");
  });

  it("does not re-read downloaded files on every idle cycle", async () => {
    const a = await makeClient(srv, "mac-a");
    for (let i = 0; i < 20; i++) a.vault.put(`n${i}.md`, `note ${i}\n`);
    await a.engine.sync();
    const b = await makeClient(srv, "iphone");
    await b.engine.sync();
    let reads = 0;
    const read = b.vault.read.bind(b.vault);
    b.vault.read = async (p: string) => (reads++, read(p));
    await b.engine.sync(); // first idle cycle may hash the fresh downloads once
    reads = 0;
    await b.engine.sync();
    await b.engine.sync();
    expect(reads).toBe(0);
  });

  // A rogue device that holds the key commits files by hand, bypassing the engine.
  async function rogueCommit(path: string, content: string, claimed = content) {
    const api = new Api(srv.url, srv.addDevice(`rogue-${uuid4().slice(0, 8)}`), fetchTransport);
    const v = await api.vault();
    const keys = await Keyring.fromMaster(await Keyring.deriveMaster(PASSPHRASE, v.kdf_salt, v.kdf_iters));
    const id = uuid4();
    const blob = await keys.encBlob(utf8.encode(content), id);
    const r = await api.commit([{
      file_id: id, base_version: 0, path_hmac: await keys.pathHmac(path), enc_path: await keys.encPath(path, id),
      content_tag: await keys.tag(utf8.encode(claimed)), blob_sha: await sha256Hex(blob), size: content.length,
      deleted: false, mtime: 0, blob: toB64(blob),
    }]);
    expect(r.results[0].ok).toBe(true);
  }

  it("never writes a remote file into .obsidian or outside the vault", async () => {
    const a = await makeClient(srv, "mac-a");
    a.vault.put("ok.md", "fine\n");
    await a.engine.sync();
    await rogueCommit(".obsidian/plugins/evil/main.js", "module.exports = pwn");
    await rogueCommit(".OBSIDIAN/plugins/evil/main.js", "same folder on case-insensitive disks");
    await rogueCommit(".Trash/x.md", "trash");
    await rogueCommit(".obsidian./plugins/evil/main.js", "Windows drops the trailing dot");
    await rogueCommit(".obſidian/plugins/evil/main.js", "long s folds to s");
    await rogueCommit("notes/x.md:stream", "NTFS stream");
    await rogueCommit(".obs\u200bidian/plugins/evil/main.js", "zero-width space");
    await rogueCommit("OBSIDI~1/plugins/evil/main.js", "Windows 8.3 alias");
    await rogueCommit("notes/.hidden.md", "Obsidian never syncs dot-files");
    await rogueCommit("../escape.md", "out");
    await rogueCommit("dir//x.md", "odd");
    await rogueCommit("notes/also-fine.md", "fine too\n");
    const b = await makeClient(srv, "iphone");
    await settle([a, b]);
    expect(Object.keys(b.vault.snapshot()).sort()).toEqual(["notes/also-fine.md", "ok.md"]);
  });

  it("refuses a blob whose content does not match its tag", async () => {
    await rogueCommit("swapped.md", "what the server sent", "what was committed");
    const b = await makeClient(srv, "iphone");
    await expect(b.engine.sync()).rejects.toBeInstanceOf(IntegrityError);
    expect(b.vault.snapshot()).toEqual({});
  });
});
