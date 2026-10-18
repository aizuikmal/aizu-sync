import { App, Modal, Notice, PluginSettingTab, Setting } from "obsidian";
import type { FileMeta } from "./core/api";
import type { GuardSummary, SyncEngine } from "./core/engine";
import { isMergeable, utf8d } from "./core/util";
import type AizuSync from "./main";

const when = (ts?: number) => (ts ? new Date(ts * 1000).toLocaleString() : "");

/** Asked before a cycle that would delete or overwrite a lot. */
export class GuardModal extends Modal {
  private answer = false;
  private done!: (ok: boolean) => void;

  constructor(app: App, private s: GuardSummary) {
    super(app);
  }

  ask(): Promise<boolean> {
    return new Promise((ok) => {
      this.done = ok;
      this.open();
    });
  }

  onOpen() {
    const { contentEl: el } = this;
    this.setTitle("Aizu Sync: large change — confirm");
    el.createEl("p", { text: "This sync would change a lot of files at once. Nothing has been touched yet." });
    const list = (label: string, xs: string[]) => {
      if (!xs.length) return;
      el.createEl("h4", { text: `${label} (${xs.length})` });
      const ul = el.createEl("ul");
      for (const x of xs.slice(0, 30)) ul.createEl("li", { text: x });
      if (xs.length > 30) ul.createEl("li", { text: `…and ${xs.length - 30} more` });
    };
    list("Delete here (deleted on another device)", this.s.localDeletes);
    list("Delete on every device (missing here)", this.s.remoteDeletes);
    list("Overwrite here with another device's version", this.s.overwrites);
    el.createEl("p", { text: "Every version stays in server history either way." });
    new Setting(el)
      .addButton((b) => b.setButtonText("Pause sync").onClick(() => this.close()))
      .addButton((b) =>
        b
          .setButtonText("Proceed")
          .setWarning()
          .onClick(() => {
            this.answer = true;
            this.close();
          }),
      );
  }

  onClose() {
    this.contentEl.empty();
    this.done(this.answer);
  }
}

/** Every server version of one file; preview and restore any of them. */
export class HistoryModal extends Modal {
  constructor(app: App, private engine: SyncEngine, private path: string, private onRestore: (path: string, data: Uint8Array) => Promise<void>) {
    super(app);
  }

  async onOpen() {
    const el = this.contentEl;
    this.setTitle(`History: ${this.path}`);
    const status = el.createEl("p", { text: "Loading…" });
    let versions: { meta: FileMeta; path: string }[];
    try {
      versions = (await this.engine.history(this.path)).reverse();
    } catch (e) {
      status.setText(`Could not load history: ${e}`);
      return;
    }
    status.setText(versions.length ? `${versions.length} versions, newest first.` : "No server history for this file yet.");
    const preview = el.createEl("pre", { cls: "aizu-sync-preview" });
    for (const v of versions) {
      const s = new Setting(el)
        .setName(when(v.meta.ts) + (v.meta.deleted ? " — deleted" : ""))
        .setDesc(`${v.path} · ${v.meta.size} bytes · device ${v.meta.device_id}`);
      if (v.meta.deleted) continue;
      s.addButton((b) =>
        b.setButtonText("Preview").onClick(async () => {
          const data = await this.engine.versionContent(v.meta);
          preview.setText(isMergeable(v.path) ? utf8d.decode(data).slice(0, 5000) : `(binary, ${data.length} bytes)`);
        }),
      );
      s.addButton((b) =>
        b.setButtonText("Restore").onClick(async () => {
          await this.onRestore(this.path, await this.engine.versionContent(v.meta));
          new Notice(`Restored ${this.path} to the version from ${when(v.meta.ts)}`);
          this.close();
        }),
      );
    }
  }

  onClose() {
    this.contentEl.empty();
  }
}

/** Files deleted on any device; restore brings back their last content. */
export class DeletedModal extends Modal {
  constructor(app: App, private engine: SyncEngine, private onRestore: (path: string, data: Uint8Array) => Promise<boolean>) {
    super(app);
  }

  async onOpen() {
    const el = this.contentEl;
    this.setTitle("Restore deleted files");
    const deleted = this.engine.deletedFiles().sort((a, b) => b.meta.version - a.meta.version);
    if (!deleted.length) el.createEl("p", { text: "Nothing has been deleted." });
    for (const d of deleted.slice(0, 200)) {
      new Setting(el)
        .setName(d.path)
        .setDesc(`deleted ${when(d.meta.ts)}`)
        .addButton((b) =>
          b.setButtonText("Restore").onClick(async () => {
            const versions = await this.engine.historyOf(d.meta.file_id);
            const last = versions.filter((v) => !v.meta.deleted).pop();
            if (!last) return void new Notice("No content to restore");
            const ok = await this.onRestore(last.path, await this.engine.versionContent(last.meta));
            new Notice(ok ? `Restored ${last.path}` : `${last.path} already exists — rename it first`);
            if (ok) b.setDisabled(true).setButtonText("Restored");
          }),
        );
    }
  }

  onClose() {
    this.contentEl.empty();
  }
}

export class SettingsTab extends PluginSettingTab {
  private passphrase = "";

  constructor(app: App, private plugin: AizuSync) {
    super(app, plugin);
  }

  display() {
    const el = this.containerEl;
    const s = this.plugin.cfg;
    el.empty();
    el.createEl("p", { text: `Status: ${this.plugin.statusText()}` });

    new Setting(el)
      .setName("Server URL")
      .setDesc("Your obsyncd server, e.g. https://sync.example.com")
      .addText((t) => t.setValue(s.serverUrl).onChange(async (v) => ((s.serverUrl = v.trim()), await this.plugin.saveSettings())));
    new Setting(el)
      .setName("Device token")
      .setDesc("From: obsyncd device add <name>")
      .addText((t) => {
        t.inputEl.type = "password";
        t.setValue(s.token).onChange(async (v) => ((s.token = v.trim()), await this.plugin.saveSettings()));
      });
    new Setting(el)
      .setName("Device name")
      .setDesc("Used in conflict copy names, e.g. MBP, Air, iPhone")
      .addText((t) => t.setValue(s.device).onChange(async (v) => ((s.device = v.trim() || "device"), await this.plugin.saveSettings())));
    new Setting(el)
      .setName("Vault passphrase")
      .setDesc(s.master ? "Connected. The derived key is stored on this device; the passphrase is not." : "Encrypts everything before it leaves this device. Same passphrase on every device.")
      .addText((t) => {
        t.inputEl.type = "password";
        t.setPlaceholder(s.master ? "(connected)" : "passphrase").onChange((v) => (this.passphrase = v));
      })
      .addButton((b) =>
        b
          .setButtonText(s.master ? "Reconnect" : "Connect")
          .setCta()
          .onClick(async () => {
            b.setDisabled(true).setButtonText("Checking…");
            await this.plugin.connect(this.passphrase);
            this.passphrase = "";
            this.display();
          }),
      );
    if (this.plugin.connectError) el.createEl("p", { text: this.plugin.connectError, cls: "aizu-sync-error" });
    new Setting(el)
      .setName("Ask before deleting more than")
      .setDesc("files in one sync")
      .addText((t) =>
        t.setValue(String(s.maxDeletes)).onChange(async (v) => {
          const n = Number(v);
          if (Number.isInteger(n) && n >= 0) {
            s.maxDeletes = n;
            await this.plugin.saveSettings();
          }
        }),
      );
    new Setting(el)
      .setName("Paused")
      .addToggle((t) => t.setValue(s.paused).onChange(async (v) => await this.plugin.setPaused(v)));
  }
}
