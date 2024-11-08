import { describe, expect, it } from "vitest";

import { PrivateKey, PublicKey } from "../src/keys";
import { decodeHex } from "../src/utils";

const ETH_SK_HEX = "0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d";
const ETH_PK_HEX =
  "0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140" +
  "a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b";

describe("test keys", () => {
  it("tests invalid", () => {
    // 0 < private key < group order int
    const groupOrderInt =
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    expect(() => new PrivateKey(decodeHex(groupOrderInt))).toThrow(Error);

    const groupOrderIntAdd1 =
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
    expect(() => new PrivateKey(decodeHex(groupOrderIntAdd1))).toThrow(Error);

    expect(() => new PrivateKey(decodeHex("0"))).toThrow(Error);
  });

  it("tests equal", () => {
    const prv = new PrivateKey();
    const pub = PublicKey.fromHex(prv.publicKey.toHex(false));

    expect(pub.equals(prv.publicKey)).toBe(true);
    expect(pub).toStrictEqual(prv.publicKey);

    expect(prv.equals(PrivateKey.fromHex(prv.toHex()))).toBe(true);
    expect(prv).toStrictEqual(PrivateKey.fromHex(prv.toHex()));
  });

  it("tests eth key compatibility", () => {
    expect(PublicKey.fromHex(ETH_PK_HEX)).toStrictEqual(
      PrivateKey.fromHex(ETH_SK_HEX).publicKey
    );
  });

  it("tests multiply and hkdf", () => {
    const two = Buffer.from(new Uint8Array(32));
    two[31] = 2;
    const three = Buffer.from(new Uint8Array(32));
    three[31] = 3;

    const k1 = new PrivateKey(two);
    const k2 = new PrivateKey(three);
    expect(k1.multiply(k2.publicKey)).toStrictEqual(k2.multiply(k1.publicKey));

    const derived = k1.encapsulate(k2.publicKey);
    const anotherDerived = k1.publicKey.decapsulate(k2);
    const knownDerived = Buffer.from(
      decodeHex("6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82")
    );
    expect(derived).toStrictEqual(knownDerived);
    expect(anotherDerived).toStrictEqual(knownDerived);
  });
});
