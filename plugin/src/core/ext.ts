// The extension hook: lets another plugin (an "add-on") use this vault's key
// and the sync server's authentication, without the passphrase or the token.
// Add-ons get it from app.plugins.getPlugin("aizu-sync")?.extension().
// Plugins already have full vault access (they could read data.json), so this
// grants nothing new; the guards only keep add-ons clear of the sync protocol.

import type { Api } from "./api";
import type { Keyring } from "./crypto";

export interface AizuSyncExtension {
  version: 1;
  /** AES-256-GCM with the vault key; `aad` binds the ciphertext to its purpose. */
  encrypt(data: Uint8Array, aad: string): Promise<Uint8Array>;
  /** Throws if the key, the data or the aad don't match. */
  decrypt(data: Uint8Array, aad: string): Promise<Uint8Array>;
  /** Authenticated request to the sync server (or a service behind the same proxy). */
  request(method: "GET" | "PUT" | "POST", path: string, body?: Uint8Array): Promise<Uint8Array>;
}

// AADs the sync engine itself uses: an add-on may never make or open those.
function checkAad(aad: string) {
  if (!aad || aad === "keycheck" || aad.startsWith("blob:") || aad.startsWith("path:")) throw new Error(`reserved aad: ${aad}`);
}

function checkPath(path: string) {
  if (!/^\/v1\/[A-Za-z0-9/_.-]+$/.test(path) || path.split("/").includes("..")) throw new Error(`bad extension path: ${path}`);
}

export function makeExtension(api: Api, keys: Keyring): AizuSyncExtension {
  return {
    version: 1,
    encrypt: async (data, aad) => (checkAad(aad), keys.encrypt(data, aad)),
    decrypt: async (data, aad) => (checkAad(aad), keys.decrypt(data, aad)),
    request: async (method, path, body) => (checkPath(path), api.request(method, path, body)),
  };
}
