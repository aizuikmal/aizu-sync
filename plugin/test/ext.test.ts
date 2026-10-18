import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Api, ApiError, fetchTransport } from "../src/core/api";
import { Keyring } from "../src/core/crypto";
import { AizuSyncExtension, makeExtension } from "../src/core/ext";
import { utf8, utf8d } from "../src/core/util";
import { PASSPHRASE, startServer, TestServer } from "./harness";

describe("extension hook", () => {
  let srv: TestServer;
  let keys: Keyring;
  let ext: AizuSyncExtension;
  beforeAll(async () => {
    srv = await startServer();
    const api = new Api(srv.url, srv.addDevice("addon"), fetchTransport);
    const v = await api.vault();
    keys = await Keyring.fromMaster(await Keyring.deriveMaster(PASSPHRASE, v.kdf_salt, v.kdf_iters));
    ext = makeExtension(api, keys);
  });
  afterAll(() => srv.stop());

  it("encrypts with the vault key, bound to the aad", async () => {
    const ct = await ext.encrypt(utf8.encode("a pasted screenshot"), "img:1");
    expect(utf8d.decode(await ext.decrypt(ct, "img:1"))).toBe("a pasted screenshot");
    expect(utf8d.decode(await keys.decrypt(ct, "img:1"))).toBe("a pasted screenshot"); // same format as the keyring
    await expect(ext.decrypt(ct, "img:2")).rejects.toThrow();
  });

  it("never touches the sync protocol's own ciphertexts", async () => {
    const blob = await keys.encBlob(utf8.encode("note"), "11111111-2222-4333-8444-555555555555");
    await expect(ext.decrypt(blob, "blob:11111111-2222-4333-8444-555555555555")).rejects.toThrow(/reserved/);
    for (const aad of ["keycheck", "path:x", "blob:x", ""]) await expect(ext.encrypt(utf8.encode("x"), aad)).rejects.toThrow(/reserved/);
  });

  it("makes authenticated requests under /v1/ only", async () => {
    const v = JSON.parse(utf8d.decode(await ext.request("GET", "/v1/vault")));
    expect(v.kdf_salt).toBeTruthy();
    await expect(ext.request("GET", "/v1/img/does-not-exist")).rejects.toBeInstanceOf(ApiError); // 404 here: no image service
    for (const p of ["/healthz", "/v1/../healthz", "/v1/a b", "v1/vault", "/v1/x?y=1"]) await expect(ext.request("GET", p)).rejects.toThrow(/bad extension path/);
  });
});
