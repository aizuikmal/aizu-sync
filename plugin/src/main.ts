import { Notice, Platform, Plugin, TFile, normalizePath } from "obsidian";
import { Api, ApiError } from "./core/api";
import { Keyring } from "./core/crypto";
import { GuardPausedError, Status, SyncEngine, VaultNotReadyError, WrongPassphraseError } from "./core/engine";
import { fromB64, isMergeable, toB64, utf8d } from "./core/util";
import { IdbState, ObsidianVault, obsidianTransport } from "./obsidian-vault";
import { DeletedModal, GuardModal, HistoryModal, SettingsTab } from "./ui";

interface Settings {
  serverUrl: string;
  token: string;
  device: string;
  master: string; // base64 derived key; never the passphrase
  maxDeletes: number;
  paused: boolean;
}

const DEFAULTS: Settings = {
  serverUrl: "",
  token: "",
  device: Platform.isMobile ? "iPhone" : "Mac",
  master: "",
  maxDeletes: 10,
  paused: false,
};

export default class AizuSync extends Plugin {
  cfg!: Settings;
  /** Last failed connect, shown in settings until the next attempt succeeds. */
  connectError = "";
  private engine?: SyncEngine;
  private api?: Api;
  private ws?: WebSocket;
  private wsBackoff = 1000;
  private timer?: number;
  private status: Status = "idle";
  private detail = "";
  private lastSync = 0;
  private statusEl?: HTMLElement;
  private stopped = false;
  private registered = false;

  async onload() {
    this.cfg = { ...DEFAULTS, ...(await this.loadData()) };
    this.addSettingTab(new SettingsTab(this.app, this));
    this.statusEl = this.addStatusBarItem();
    this.addRibbonIcon("refresh-cw", "Aizu Sync: sync now", () => this.syncNow(true));

    this.addCommand({ id: "sync-now", name: "Sync now", callback: () => this.syncNow(true) });
    this.addCommand({ id: "toggle-pause", name: "Pause / resume sync", callback: () => this.setPaused(!this.cfg.paused) });
    this.addCommand({
      id: "file-history",
      name: "File history (current file)",
      checkCallback: (checking) => {
        const f = this.app.workspace.getActiveFile();
        if (!f || !this.engine) return false;
        if (!checking) new HistoryModal(this.app, this.engine, f.path, (p, d) => this.restoreInto(p, d)).open();
        return true;
      },
    });
    this.addCommand({
      id: "restore-deleted",
      name: "Restore deleted files",
      checkCallback: (checking) => {
        if (!this.engine) return false;
        if (!checking) new DeletedModal(this.app, this.engine, (p, d) => this.restoreNew(p, d)).open();
        return true;
      },
    });
    this.addCommand({
      id: "verify",
      name: "Verify vault against server",
      checkCallback: (checking) => {
        if (!this.engine) return false;
        if (!checking) void this.verify();
        return true;
      },
    });

    this.app.workspace.onLayoutReady(() => void this.start());
  }

  onunload() {
    this.stopped = true;
    window.clearTimeout(this.timer);
    this.ws?.close();
  }

  async saveSettings() {
    await this.saveData(this.cfg);
  }

  statusText(): string {
    if (!this.cfg.master) return "not connected";
    if (this.cfg.paused) return "paused";
    const at = this.lastSync ? ` · last ${new Date(this.lastSync).toLocaleTimeString()}` : "";
    return `${this.status}${this.detail && this.status !== "idle" ? ` (${this.detail})` : ""}${at}`;
  }

  private paint() {
    const icon = { idle: "✓", syncing: "⟳", offline: "⚠ offline", paused: "⏸", error: "✕" }[this.cfg.paused ? "paused" : this.status];
    this.statusEl?.setText(`Sync ${icon}`);
    this.statusEl?.setAttr("aria-label", this.statusText());
  }

  private setStatus = (s: Status, detail = "") => {
    const was = this.status;
    this.status = s;
    this.detail = detail;
    if (s === "idle") this.lastSync = Date.now();
    if (s === "error" && was !== "error") new Notice(`Aizu Sync error: ${detail}`, 10000);
    this.paint();
  };

  /** Derives the key from the passphrase, checks it against the vault, saves it. */
  async connect(passphrase: string): Promise<boolean> {
    const s = this.cfg;
    if (!s.serverUrl || !s.token || !passphrase) {
      new Notice("Fill in server URL, device token and passphrase first");
      return false;
    }
    try {
      const api = new Api(s.serverUrl, s.token, obsidianTransport);
      const v = await api.vault();
      const master = await Keyring.deriveMaster(passphrase, v.kdf_salt, v.kdf_iters);
      const probe = new SyncEngine({ api, keys: await Keyring.fromMaster(master), vault: new ObsidianVault(this.app), state: this.state(), device: s.device });
      await probe.init(); // throws WrongPassphraseError
      s.master = toB64(master);
      this.connectError = "";
      await this.saveSettings();
      new Notice("Aizu Sync connected");
      await this.start();
      return true;
    } catch (e) {
      if (e instanceof WrongPassphraseError) this.connectError = "Wrong passphrase. Nothing was saved or uploaded" + (s.master ? "; still using the previous key." : ".");
      else if (e instanceof VaultNotReadyError) this.connectError = "This vault has no passphrase set up on the server yet. Nothing was saved or uploaded.";
      else if (e instanceof ApiError && e.status === 401) this.connectError = "Device token rejected by the server.";
      else this.connectError = `Could not connect: ${e}`;
      new Notice(`Aizu Sync: ${this.connectError}`, 10000);
      return false;
    }
  }

  private state() {
    return new IdbState(`aizu-sync:${this.app.vault.getName()}`);
  }

  private async start() {
    const s = this.cfg;
    this.ws?.close();
    this.engine = undefined;
    if (!s.serverUrl || !s.token || !s.master) return this.paint();
    this.api = new Api(s.serverUrl, s.token, obsidianTransport);
    const keys = await Keyring.fromMaster(fromB64(s.master));
    const engine = new SyncEngine({
      api: this.api,
      keys,
      vault: new ObsidianVault(this.app),
      state: this.state(),
      device: s.device,
      configDir: this.app.vault.configDir,
      maxDeletes: s.maxDeletes,
      guard: (g) => new GuardModal(this.app, g).ask(),
      onStatus: this.setStatus,
      onConflict: (p, copy) => new Notice(`Aizu Sync: conflicting edits in ${p}. Your other version was kept as ${copy}`, 15000),
      log: (m) => console.log("[aizu-sync]", m),
    });
    try {
      await engine.init();
    } catch (e) {
      this.setStatus(e instanceof WrongPassphraseError ? "error" : "offline", String(e));
      if (!(e instanceof WrongPassphraseError)) window.setTimeout(() => !this.stopped && void this.start(), 30000);
      return;
    }
    this.engine = engine;

    if (!this.registered) {
      this.registered = true;
      const v = this.app.vault;
      this.registerEvent(v.on("create", () => this.schedule()));
      this.registerEvent(v.on("modify", () => this.schedule()));
      this.registerEvent(v.on("delete", () => this.schedule()));
      this.registerEvent(
        v.on("rename", (f, old) => {
          this.engine?.noteRename(old, f.path);
          this.schedule();
        }),
      );
      this.registerInterval(window.setInterval(() => this.schedule(0), 30000));
      // iOS: the app is frozen in the background; catch up the moment it is shown.
      this.registerDomEvent(document, "visibilitychange", () => {
        if (document.visibilityState === "visible") this.wake();
      });
      this.registerDomEvent(window, "focus", () => this.wake());
    }
    this.connectWs();
    this.schedule(0);
  }

  private wake() {
    if (!this.ws || this.ws.readyState > WebSocket.OPEN) this.connectWs();
    this.schedule(0);
  }

  private connectWs() {
    if (!this.api || this.stopped) return;
    this.ws?.close();
    const ws = new WebSocket(this.api.wsUrl());
    this.ws = ws;
    ws.onopen = () => {
      this.wsBackoff = 1000;
      ws.send(JSON.stringify({ token: this.cfg.token }));
    };
    ws.onmessage = (ev) => {
      try {
        const m = JSON.parse(String(ev.data)) as { type: string; head: number };
        if (this.engine && m.head > this.engine.head) this.schedule(m.type === "hello" ? 0 : 250);
      } catch {
        /* ignore */
      }
    };
    ws.onclose = () => {
      if (this.ws !== ws || this.stopped) return;
      this.wsBackoff = Math.min(this.wsBackoff * 2, 60000);
      window.setTimeout(() => this.ws === ws && this.connectWs(), this.wsBackoff);
    };
  }

  private schedule(ms = 750) {
    window.clearTimeout(this.timer);
    this.timer = window.setTimeout(() => void this.runSync(), ms);
  }

  private async runSync(manual = false) {
    if (!this.engine || this.cfg.paused) return;
    try {
      await this.engine.sync();
      if (manual) new Notice("Aizu Sync: up to date");
    } catch (e) {
      if (e instanceof GuardPausedError) {
        await this.setPaused(true);
        new Notice("Aizu Sync paused. Nothing was changed. Resume from the command palette when ready.", 15000);
      } else if (manual) new Notice(`Aizu Sync: ${e}`);
    }
  }

  private syncNow(manual: boolean) {
    if (!this.engine) return void new Notice("Aizu Sync is not connected — see its settings");
    window.clearTimeout(this.timer);
    void this.runSync(manual);
  }

  async setPaused(p: boolean) {
    this.cfg.paused = p;
    await this.saveSettings();
    this.paint();
    if (!p) this.schedule(0);
  }

  /** History restore: becomes a normal local edit, which then syncs. */
  private async restoreInto(path: string, data: Uint8Array) {
    const f = this.app.vault.getFileByPath(path);
    if (!(f instanceof TFile)) return;
    if (isMergeable(path)) await this.app.vault.modify(f, utf8d.decode(data));
    else await this.app.vault.modifyBinary(f, data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer);
  }

  private async restoreNew(path: string, data: Uint8Array): Promise<boolean> {
    return new ObsidianVault(this.app).create(normalizePath(path), data);
  }

  private async verify() {
    new Notice("Aizu Sync: verifying…");
    const r = await this.engine!.verify();
    const bad = r.differ.length + r.localOnly.length + r.remoteOnly.length;
    new Notice(
      bad
        ? `Aizu Sync verify: ${r.ok} match, ${r.differ.length} differ, ${r.localOnly.length} only here, ${r.remoteOnly.length} only on server (details in console)`
        : `Aizu Sync verify: all ${r.ok} files match the server`,
      15000,
    );
    if (bad) console.log("[aizu-sync] verify", r);
  }
}
