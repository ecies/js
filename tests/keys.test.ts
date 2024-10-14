import { describe, expect, it } from "vitest";

import { PrivateKey, PublicKey } from "../src/keys";
import { decodeHex } from "../src/utils";

const ETH_PRVHEX = "0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d";
const ETH_PUBHEX =
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

    const isPubEqual = pub.uncompressed.equals(prv.publicKey.uncompressed);
    expect(isPubEqual).toEqual(true);

    const isFromHexWorking = prv.equals(PrivateKey.fromHex(prv.toHex()));
    expect(isFromHexWorking).toEqual(true);
  });

  it("tests eth key compatibility", () => {
    const ethPrv = PrivateKey.fromHex(ETH_PRVHEX);
    const ethPub = PublicKey.fromHex(ETH_PUBHEX);
    expect(ethPub.equals(ethPrv.publicKey)).toEqual(true);
  });

  it("tests multiply and hkdf", () => {
    const two = Buffer.from(new Uint8Array(32));
    two[31] = 2;
    const three = Buffer.from(new Uint8Array(32));
    three[31] = 3;

    const k1 = new PrivateKey(two);
    const k2 = new PrivateKey(three);
    expect(k1.multiply(k2.publicKey).equals(k2.multiply(k1.publicKey))).toEqual(true);

    const derived = k1.encapsulate(k2.publicKey);
    const anotherDerived = k1.publicKey.decapsulate(k2);
    const knownDerived = Buffer.from(
      decodeHex("6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82")
    );
    expect(derived.equals(knownDerived)).toEqual(true);
    expect(anotherDerived.equals(knownDerived)).toEqual(true);
  });
});
