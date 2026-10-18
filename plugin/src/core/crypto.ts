// End-to-end encryption. The server only ever sees:
//   blob      = iv(12) || AES-256-GCM(content, aad "blob:<file_id>")
//   enc_path  = base64(iv || AES-256-GCM(path, aad "path:<file_id>"))
//   path_hmac = HMAC-SHA256(macKey, "path\0" || NFC(path))
//   tag       = HMAC-SHA256(macKey, "content\0" || content)
// Keys: PBKDF2-SHA256(passphrase, vault salt) -> master -> HKDF -> enc / mac.

import { concat, fromB64, normPath, toB64, toHex, utf8, utf8d } from "./util";

const subtle = globalThis.crypto.subtle;
// WebCrypto wants ArrayBuffer-backed views; ours always are.
const bs = (u: Uint8Array) => u as Uint8Array<ArrayBuffer>;
const KEY_CHECK = "aizu-sync key check v1";

export class Keyring {
  private constructor(
    private enc: CryptoKey,
    private mac: CryptoKey,
  ) {}

  /** Raw master bytes are what devices cache, so the passphrase itself is never stored. */
  static async deriveMaster(passphrase: string, saltB64: string, iters: number): Promise<Uint8Array> {
    const base = await subtle.importKey("raw", bs(utf8.encode(passphrase.normalize("NFC"))), "PBKDF2", false, ["deriveBits"]);
    const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: bs(fromB64(saltB64)), iterations: iters }, base, 256);
    return new Uint8Array(bits);
  }

  static async fromMaster(master: Uint8Array): Promise<Keyring> {
    const hk = await subtle.importKey("raw", bs(master), "HKDF", false, ["deriveKey"]);
    const info = (s: string) => ({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: bs(utf8.encode(s)) });
    const enc = await subtle.deriveKey(info("aizu-sync enc v1"), hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const mac = await subtle.deriveKey(info("aizu-sync mac v1"), hk, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);
    return new Keyring(enc, mac);
  }

  async encrypt(data: Uint8Array, aad: string): Promise<Uint8Array> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: bs(utf8.encode(aad)) }, this.enc, bs(data));
    return concat(iv, new Uint8Array(ct));
  }

  /** Throws if the key is wrong or the data/aad was tampered with. */
  async decrypt(blob: Uint8Array, aad: string): Promise<Uint8Array> {
    const pt = await subtle.decrypt({ name: "AES-GCM", iv: bs(blob.subarray(0, 12)), additionalData: bs(utf8.encode(aad)) }, this.enc, bs(blob.subarray(12)));
    return new Uint8Array(pt);
  }

  private async hmac(prefix: string, data: Uint8Array): Promise<string> {
    return toHex(await subtle.sign("HMAC", this.mac, bs(concat(utf8.encode(prefix + "\0"), data))));
  }

  tag(content: Uint8Array): Promise<string> {
    return this.hmac("content", content);
  }

  pathHmac(path: string): Promise<string> {
    return this.hmac("path", utf8.encode(normPath(path)));
  }

  async encPath(path: string, fileId: string): Promise<string> {
    return toB64(await this.encrypt(utf8.encode(normPath(path)), "path:" + fileId));
  }

  async decPath(enc: string, fileId: string): Promise<string> {
    return utf8d.decode(await this.decrypt(fromB64(enc), "path:" + fileId));
  }

  encBlob(content: Uint8Array, fileId: string): Promise<Uint8Array> {
    return this.encrypt(content, "blob:" + fileId);
  }

  decBlob(blob: Uint8Array, fileId: string): Promise<Uint8Array> {
    return this.decrypt(blob, "blob:" + fileId);
  }

  async makeKeyCheck(): Promise<string> {
    return toB64(await this.encrypt(utf8.encode(KEY_CHECK), "keycheck"));
  }

  /** False = this passphrase is not the vault's. Such a device must never upload. */
  async verifyKeyCheck(kc: string): Promise<boolean> {
    try {
      return utf8d.decode(await this.decrypt(fromB64(kc), "keycheck")) === KEY_CHECK;
    } catch {
      return false;
    }
  }
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  return toHex(await subtle.digest("SHA-256", bs(data)));
}
