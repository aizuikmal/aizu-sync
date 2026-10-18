# Aizu Sync

Self-hosted, end-to-end encrypted sync for [Obsidian](https://obsidian.md): a replacement for the official Obsidian Sync that you run on your own machine.

- **Real-time:** an edit shows up on your other devices in about a second, and the iPhone catches up as soon as you open the app.
- **Merges, not overwrites:** concurrent edits to the same note are merged line by line, the same approach Obsidian Sync takes. When a clean merge is impossible, both versions are kept.
- **Full version history:** every version of every file, deletions included. You can browse and restore it from inside Obsidian.
- **End-to-end encrypted:** the server stores only ciphertext. File contents *and* file names are encrypted on the device, so the server, its disk and its backups never see your notes.
- **Small and boring server:** one static Go binary with SQLite. It doesn't merge, interpret or rewrite anything.

It runs on macOS, Windows, Linux, iOS and Android, wherever Obsidian runs.

> Status: used daily on a ~1,250-note vault across two Macs and an iPhone.
> Provided as-is, without support. Read [Security](#security) before deploying.

## How it works

```
 device ── encrypt, diff, 3-way merge ──┐
 device ── encrypt, diff, 3-way merge ──┼── HTTPS ──► reverse proxy ──► obsyncd ── SQLite (metadata, history)
 device ── encrypt, diff, 3-way merge ──┘                                       └─ blobs/ (ciphertext)
```

**The server (`obsyncd`) is dumb on purpose.** It stores encrypted whole-file blobs and an append-only version log, and accepts a change only if the device built it on the latest version (compare-and-swap). A WebSocket tells devices when something changed.

**Devices do the thinking.**
- **Detecting changes:**
  - Vault events.
  - A startup scan, which catches edits made while Obsidian was closed (by scripts, git, other editors).
  - A pull when the app comes back to the foreground.
- **Pushing:** encrypt, upload, commit with the base version. If another device got there first (HTTP 409), the device fetches both sides, merges and retries.
- **Merge rules:**
  - Markdown and text: a line-level 3-way merge (`node-diff3`). If that conflicts, the device's patches are re-applied onto the server copy (`diff-match-patch`), accepted only if every patch applies. If both fail, the server version stays and the device's version is saved next to it as `Note (conflict <device> <date>).md`.
  - Binary files and `.canvas`: the newest wins, and the other side becomes a conflict copy.
  - Edit vs. delete: the edit wins, and the file comes back.
  - Rename vs. edit: both apply, because files are identified by id, not by path.
- **Guards:**
  - A sync that would delete or overwrite a lot of files pauses and asks first.
  - The first sync on a new device never deletes anything.
  - Local deletions go to the system trash.
- **Losing the device's local sync state can't lose data:** it is only a cache and is rebuilt by comparing content hashes with the server.

The repository includes a randomized simulator (`sim/run.ts`). It runs three devices against a real server through thousands of random edit, rename, delete, offline, crash and state-wipe sequences, then checks two things:
- all devices converge byte for byte;
- no line any user wrote is lost.

## Security

### Encryption
- **Keys:** `PBKDF2-SHA256(passphrase, per-vault salt, 600k iterations)` gives a master key, and HKDF derives separate encryption and MAC keys from it. The cipher is AES-256-GCM.
- **Binding:** every ciphertext is bound to its file id (AAD), so the server can't swap one file's content or name for another's without decryption failing.
- **Comparing without plaintext:** paths and contents are compared through HMACs, so the server can enforce "one live file per path" and devices can skip unchanged files, all without plaintext.
- **Passphrase:** set once by the admin on the server (`obsyncd set-passphrase`). The server keeps only a *key check* derived from it, never the passphrase. A device with the wrong passphrase is refused before it can upload anything. Devices cache the derived key, not the passphrase.
- **Integrity:** a device verifies every download against its MAC, so a tampered blob is rejected.
- **What the server can see:** file sizes, timing, which device made each change, and how many files there are.
- **What a malicious server could still do:** it can't read or forge content, but it controls *freshness*. It could withhold new changes, or present an older version you really did write as the current one. Nothing is lost (every version stays in history), but commits aren't yet signed into a per-file chain that would detect this.
- **Paths from other devices are checked before anything is written:**
  - No `..`, absolute paths, control characters, colons, or names ending in a dot or space.
  - Nothing ever goes into `.obsidian/`, `.trash/` or `.git/` under any spelling the filesystem would accept: names are case-folded, and the trailing dots and spaces that Windows ignores are stripped, so `.OBSIDIAN` and `.obsidian.` are caught too.
  - This also covers restoring from history.

### Access
- **Device tokens:** every request needs a per-device bearer token (256-bit, stored hashed). Tokens can be revoked one at a time, and a revoked device's live connection is closed.
- **Device cap:** the number of active devices is capped (`device add -max N`).

### Deployment advice
- **Don't expose the server to the public internet.** Run it on a private network or behind a VPN, so that only your own devices can reach it at all. Encryption protects your notes' content either way, but there's no reason to let strangers talk to your server.
- `obsyncd` listens on localhost by default; put an HTTPS reverse proxy in front (Caddy config included). Obsidian on iOS needs a certificate it trusts.
- Keep the passphrase in a password manager. **If it's lost, the server data and its backups can't be decrypted.** Your devices still hold plain copies of the vault.

## Run with Docker

Requirements:
- Docker with Compose.
- A host your devices can reach, ideally only over a private network or VPN.
- A domain name for HTTPS.

```sh
git clone https://github.com/aizuikmal/aizu-sync && cd aizu-sync/deploy
cp .env.example .env                   # set SYNC_DOMAIN and BIND_ADDR
cp Caddyfile.example Caddyfile         # choose a TLS option inside (see below)

# 1. Create the vault (once)
docker compose run --rm obsyncd init

# 2. Set the vault passphrase (once). -generate prints a strong one; store it in a password manager.
docker compose run --rm obsyncd set-passphrase -generate
#    or type your own (min 12 printable ASCII characters):
#    docker compose run --rm -it obsyncd set-passphrase

# 3. Start
docker compose up -d --build

# 4. One token per device (printed once)
docker compose exec obsyncd obsyncd device add macbook
docker compose exec obsyncd obsyncd device add iphone
```

In `.env`, `BIND_ADDR` is the host address Caddy listens on. Use your private or VPN interface address, not `0.0.0.0`.

**TLS options** (in `Caddyfile`):
- **(A) Public :443 reachable:** automatic Let's Encrypt, nothing to configure.
- **(B) Private network (recommended):** a DNS-01 challenge. Build Caddy with your DNS provider's module (`caddy-dns.Dockerfile`, Cloudflare shown) and set `DNS_API_TOKEN`. Point the domain's DNS record at the server's private address: it resolves publicly but is reachable only from your network.
- **(C) No domain:** `tls internal`, then install Caddy's root certificate on every device.

All server data lives in the `obsync-data` volume.

## Run without Docker (systemd)

```sh
cd server && CGO_ENABLED=0 go build -o obsyncd .     # Go 1.26+; static binary, no cgo
sudo install -m 0755 obsyncd /usr/local/bin/
sudo useradd --system --home /var/lib/obsync --shell /usr/sbin/nologin obsync
sudo install -d -o obsync -g obsync -m 0700 /var/lib/obsync
sudo -u obsync obsyncd init
sudo -u obsync obsyncd set-passphrase -generate
sudo -u obsync obsyncd device add macbook
sudo cp ../deploy/systemd/obsyncd.service /etc/systemd/system/
sudo systemctl enable --now obsyncd                    # listens on 127.0.0.1:8787
```

Then put a reverse proxy with HTTPS in front of `127.0.0.1:8787` (see `deploy/Caddyfile.example`). The unit is sandboxed: read-only system, no home access, no capabilities, 256 MB memory cap.

## Install the plugin

The plugin isn't in Obsidian's community directory yet. Install it manually:

1. Build it: `cd plugin && npm ci && npm run build`. Or take `main.js`, `manifest.json` and `styles.css` from a release.
2. Copy those three files into `<your vault>/.obsidian/plugins/aizu-sync/`.
   - On iOS: Files app → On My iPhone → Obsidian → `<vault>` → `.obsidian/plugins/aizu-sync/`.
   - Or copy them over USB with Finder's iPhone "Files" tab.
3. Obsidian → Settings → Community plugins → enable **Aizu Sync**.
4. In its settings, enter:
   - **Server URL:** e.g. `https://sync.example.com`.
   - **Device token:** from `device add`.
   - **Device name.**
   - **Vault passphrase.**

   Then press **Connect**. A wrong passphrase is rejected and nothing is saved.

**First device:** start with your existing vault. It uploads everything.

**Other devices:**
- Start from an empty vault folder (fastest), or from a copy of the vault.
- With a copy, files with identical content are adopted, differing ones are merged or kept as conflict copies, and nothing is deleted on the first sync.

**Commands** (command palette):
- Sync now
- Pause / resume sync
- File history (current file)
- Restore deleted files
- Verify vault against server

**Not synced:**
- `.obsidian/` (settings, themes, plugins)
- `.trash/`
- `.DS_Store`

The plugin's own `data.json` holds the device token and derived key, and never leaves the device.

## Administration

```
obsyncd [-data DIR] serve [-listen 127.0.0.1:8787]
obsyncd [-data DIR] init [-iters N]               create the vault (salt, KDF params)
obsyncd [-data DIR] set-passphrase [-generate]    set the vault passphrase (once; never stored)
obsyncd [-data DIR] set-key-check                 stdin: a key_check made elsewhere (advanced)
obsyncd [-data DIR] device add [-max 10] NAME     prints the device token once
obsyncd [-data DIR] device list
obsyncd [-data DIR] device revoke NAME
obsyncd [-data DIR] verify                        SQLite integrity check + re-hash every blob
obsyncd [-data DIR] snapshot OUT.db               consistent DB copy for backups
obsyncd [-data DIR] gc [-apply]                   list (or remove) unreferenced blobs older than 1h
```

`-data` defaults to `$OBSYNC_DATA`, otherwise `/var/lib/obsync`. With Docker, run these as `docker compose exec obsyncd obsyncd …`.

**Lost a device?** Run `device revoke NAME`. Its token stops working immediately.

## Backups

Every device holds a full plain copy of the vault, and the server keeps every version. Still, back up the server:
- `deploy/systemd/obsync-backup.sh` takes a consistent `snapshot` of the database plus the blob store and sends them to [restic](https://restic.net). An append-only repository is ideal, so a compromised server can't delete its backups.
- The script comes with a nightly timer, plus a weekly `verify` timer.

**Test a restore** now and then:
1. Restore into a scratch directory.
2. Run `obsyncd -data <dir> serve` on it.
3. Run `sim/restore-drill.ts`. It downloads and decrypts everything and compares it byte for byte with a local vault folder.

## Development

```sh
cd server && go test -race ./...
cd plugin && npm ci && npx tsc --noEmit -p . && npx vitest run   # builds and starts a real obsyncd
bash sim/run-parallel.sh 1000 80 8                                # randomized 3-device simulator
```

`sim/` also has read-only tools that use a vault's own key:
- `inspect.ts`: a decrypted view of what the server holds.
- `restore-drill.ts`.
- `profile.ts`: sync timing on a real folder.

## Limitations

- **No `.obsidian` sync.** Settings, themes and plugins are not synced.
- **No background sync on iOS.** No plugin can do it; Obsidian Sync can't either. The app syncs when it's open.
- **No live co-editing.** There's no shared cursor or CRDT; concurrent edits are merged when they're saved.
- **History is never pruned.** The vault only grows, but that's fine for text.
- **One vault per server.** Run one instance per vault.

## License

[MIT](LICENSE)
