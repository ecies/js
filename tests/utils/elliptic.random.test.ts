import { describe, expect, it } from "vitest";

import type { EllipticCurve } from "../../src/config";
import { getValidSecret, isValidPrivateKey } from "../../src/utils";

describe("test random elliptic", () => {
  function testRandom(curve?: EllipticCurve) {
    const key = getValidSecret(curve);
    expect(isValidPrivateKey(key, curve)).toBe(true);
  }

  it("tests secp256k1", () => {
    testRandom("secp256k1");
  });

  it("tests x25519", () => {
    testRandom("x25519");
  });

  it("tests ed25519", () => {
    testRandom("ed25519");
  });
});
