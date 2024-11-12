import { describe, expect, it } from "vitest";

import { PrivateKey, PublicKey } from "../../src";
import { decodeHex } from "../../src/utils";

describe("test known keys", () => {
  function checkHkdf(
    k1: PrivateKey,
    k2: PrivateKey,
    knownHex: string,
    compressed: boolean
  ) {
    const known = decodeHex(knownHex);
    expect(k1.encapsulate(k2.publicKey, compressed)).toStrictEqual(known);
    expect(k1.publicKey.decapsulate(k2, compressed)).toStrictEqual(known);
  }

  it("tests eth key compatibility", () => {
    const sk = PrivateKey.fromHex(
      "0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d"
    );
    const pk = PublicKey.fromHex(
      "0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140" +
        "a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b"
    );
    expect(pk).toStrictEqual(sk.publicKey);
    expect(pk.equals(sk.publicKey)).toBe(true);

    expect(pk.toHex(true)).toStrictEqual(
      "0398afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140"
    );
    expect(pk.toHex(false)).toStrictEqual(
      "0498afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140" +
        "a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b"
    );
  });

  it("tests hkdf", () => {
    const two = new Uint8Array(32);
    two[31] = 2;
    const three = new Uint8Array(32);
    three[31] = 3;

    const k1 = new PrivateKey(two);
    const k2 = new PrivateKey(three);
    expect(k1.secret).toStrictEqual(Buffer.from(two));
    expect(k2.secret).toStrictEqual(Buffer.from(three));

    checkHkdf(
      k1,
      k2,
      "6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82",
      false
    );

    checkHkdf(
      k1,
      k2,
      "b192b226edb3f02da11ef9c6ce4afe1c7e40be304e05ae3b988f4834b1cb6c69",
      true
    );
  });
});
