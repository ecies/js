import { describe, expect, it } from "vitest";

import { ECIES_CONFIG, PrivateKey, PublicKey } from "../../src";

describe("test random keys", () => {
  function check(k1: PrivateKey, k2: PrivateKey) {
    expect(k1.multiply(k2.publicKey)).toStrictEqual(k2.multiply(k1.publicKey));
  }

  function checkHex(sk: PrivateKey) {
    const skFromHex = PrivateKey.fromHex(sk.toHex());
    const pkFromHex = PublicKey.fromHex(sk.publicKey.toHex(false));

    expect(skFromHex).toStrictEqual(sk);
    expect(pkFromHex).toStrictEqual(sk.publicKey);
  }

  function testRandom() {
    const k1 = new PrivateKey();
    const k2 = new PrivateKey();
    check(k1, k2);

    const sk = new PrivateKey();
    checkHex(sk);
  }

  it("tests secp256k1", () => {
    testRandom();
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
