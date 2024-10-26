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
    expect(Buffer.from(decodeHex(sk.toHex()))).toStrictEqual(sk.secret);
    expect(PrivateKey.fromHex(sk.toHex())).toStrictEqual(sk);
    expect(PublicKey.fromHex(sk.publicKey.toHex(compressed))).toStrictEqual(sk.publicKey);
  }

  function testRandom(compressed: boolean = false) {
    checkMultiply(new PrivateKey(), new PrivateKey(), compressed);
    checkEncapsulate(new PrivateKey(), new PrivateKey(), compressed);
    checkHex(new PrivateKey(), compressed);
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
