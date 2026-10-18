import { describe, expect, it } from "vitest";
import { Keyring } from "../src/core/crypto";
import { utf8, utf8d } from "../src/core/util";

const salt = "AAAAAAAAAAAAAAAAAAAAAA==";

describe("Keyring", async () => {
  const k = await Keyring.fromMaster(await Keyring.deriveMaster("pass one", salt, 1000));
  const other = await Keyring.fromMaster(await Keyring.deriveMaster("pass two", salt, 1000));
  const id = "11111111-2222-4333-8444-555555555555";

  it("round-trips content and paths", async () => {
    const blob = await k.encBlob(utf8.encode("secret note"), id);
    expect(utf8d.decode(await k.decBlob(blob, id))).toBe("secret note");
    expect(await k.decPath(await k.encPath("Private/Health.md", id), id)).toBe("Private/Health.md");
  });

  it("ciphertext carries no plaintext and is randomized", async () => {
    const a = await k.encBlob(utf8.encode("secret note"), id);
    const b = await k.encBlob(utf8.encode("secret note"), id);
    expect(utf8d.decode(a)).not.toContain("secret");
    expect(a).not.toEqual(b);
  });

  it("binds a blob to its file id (no swapping blobs between files)", async () => {
    const blob = await k.encBlob(utf8.encode("x"), id);
    await expect(k.decBlob(blob, "99999999-2222-4333-8444-555555555555")).rejects.toThrow();
  });

  it("rejects a wrong key", async () => {
    const blob = await k.encBlob(utf8.encode("x"), id);
    await expect(other.decBlob(blob, id)).rejects.toThrow();
    expect(await other.verifyKeyCheck(await k.makeKeyCheck())).toBe(false);
    expect(await k.verifyKeyCheck(await k.makeKeyCheck())).toBe(true);
  });

  it("path hmac is stable, NFC-normalized and key-dependent", async () => {
    const nfc = "Café.md".normalize("NFC");
    const nfd = "Café.md".normalize("NFD");
    expect(await k.pathHmac(nfc)).toBe(await k.pathHmac(nfd));
    expect(await k.pathHmac(nfc)).not.toBe(await other.pathHmac(nfc));
    expect(await k.tag(utf8.encode("a"))).not.toBe(await k.tag(utf8.encode("b")));
  });
});

// Made by `obsyncd set-passphrase` (server/keycheck.go); server_test.go checks the reverse.
describe("key_check from the Go server", async () => {
  const k = await Keyring.fromMaster(await Keyring.deriveMaster("correct-horse-battery-staple", "AAECAwQFBgcICQoLDA0ODw==", 1000));
  const goKeyCheck = "0HhRT+8tR55PKqGY8GzIvfNdbYY/SYP351d1SagXouB839Jg2NNEsFqHfTtER6jgL+A="; // gitleaks:allow (test vector from a public example passphrase)

  it("verifies with the same passphrase only", async () => {
    expect(await k.verifyKeyCheck(goKeyCheck)).toBe(true);
    const wrong = await Keyring.fromMaster(await Keyring.deriveMaster("correct-horse-battery-stapl", "AAECAwQFBgcICQoLDA0ODw==", 1000));
    expect(await wrong.verifyKeyCheck(goKeyCheck)).toBe(false);
  });
});
