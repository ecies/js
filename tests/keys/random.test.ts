import { describe, expect, it } from "vitest";

import { ECIES_CONFIG, PrivateKey, PublicKey } from "../../src";
import { decodeHex } from "../../src/utils";

describe("test random keys", () => {
  function checkMultiply(k1: PrivateKey, k2: PrivateKey, compressed: boolean) {
    expect(k1.multiply(k2.publicKey, compressed)).toStrictEqual(
      k2.multiply(k1.publicKey, compressed)
    );
  }

  function checkEncapsulate(k1: PrivateKey, k2: PrivateKey, compressed: boolean) {
    expect(k1.encapsulate(k2.publicKey, compressed)).toStrictEqual(
      k1.publicKey.decapsulate(k2, compressed)
    );
    expect(k2.encapsulate(k1.publicKey, compressed)).toStrictEqual(
      k2.publicKey.decapsulate(k1, compressed)
    );
  }

  function checkHex(sk: PrivateKey, compressed: boolean) {
    expect(new PrivateKey(decodeHex(sk.toHex()))).toStrictEqual(sk);
    expect(PrivateKey.fromHex(sk.toHex())).toStrictEqual(sk);
    expect(PublicKey.fromHex(sk.publicKey.toHex(compressed))).toStrictEqual(sk.publicKey);
  }

  function checkBytes(sk: PrivateKey) {
    expect(Buffer.from(sk.publicKey.toBytes())).toStrictEqual(sk.publicKey.compressed);
    expect(Buffer.from(sk.publicKey.toBytes(false))).toStrictEqual(
      sk.publicKey.uncompressed
    );
  }

  function checkEquals(k1: PrivateKey, k2: PrivateKey) {
    expect(k1).toStrictEqual(k1);
    expect(k1).not.toStrictEqual(k2);
    expect(k1.publicKey).toStrictEqual(k1.publicKey);
    expect(k1.publicKey).not.toStrictEqual(k2.publicKey);

    expect(k1.equals(k1)).toBe(true);
    expect(k1.equals(k2)).toBe(false);
    expect(k1.publicKey.equals(k1.publicKey)).toBe(true);
    expect(k1.publicKey.equals(k2.publicKey)).toBe(false);
  }

  function testRandom(compressed: boolean = false) {
    checkMultiply(new PrivateKey(), new PrivateKey(), compressed);
    checkEncapsulate(new PrivateKey(), new PrivateKey(), compressed);
    checkHex(new PrivateKey(), compressed);
    checkBytes(new PrivateKey());
    checkEquals(new PrivateKey(), new PrivateKey());
  }

  it("tests secp256k1", () => {
    testRandom();
    testRandom(true);
  });

  it("tests x25519", () => {
    ECIES_CONFIG.ellipticCurve = "x25519";
    testRandom();
    ECIES_CONFIG.ellipticCurve = "secp256k1";
  });

  it("tests ed25519", () => {
    ECIES_CONFIG.ellipticCurve = "ed25519";
    testRandom();
    ECIES_CONFIG.ellipticCurve = "secp256k1";
  });
});
