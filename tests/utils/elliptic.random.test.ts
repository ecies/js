import { describe, expect, it } from "vitest";

import { ECIES_CONFIG } from "../../src";
import { getValidSecret, isValidPrivateKey } from "../../src/utils";

describe("test random elliptic", () => {
  function testRandom() {
    const key = getValidSecret();
    expect(isValidPrivateKey(key)).toBe(true);
  }

  it("tests secp256k1", () => {
    ECIES_CONFIG.ellipticCurve = "secp256k1";
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
