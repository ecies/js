import { describe, expect, it } from "vitest";

import {
  ECIES_CONFIG,
  ellipticCurve,
  ephemeralKeySize,
  isEphemeralKeyCompressed,
  isHkdfKeyCompressed,
  symmetricAlgorithm,
  symmetricNonceLength,
} from "../src/config";

describe("test config", () => {
  it('tests global object "ECIES_CONFIG"', async () => {
    expect(ECIES_CONFIG.ellipticCurve).toBe("secp256k1");
    expect(ECIES_CONFIG.isEphemeralKeyCompressed).toBe(false);
    expect(ECIES_CONFIG.isHkdfKeyCompressed).toBe(false);
    expect(ECIES_CONFIG.ephemeralKeySize).toBe(65);
    expect(ECIES_CONFIG.symmetricAlgorithm).toBe("aes-256-gcm");
    expect(ECIES_CONFIG.symmetricNonceLength).toBe(16);
  });

  it("tests deprecated", async () => {
    expect(ellipticCurve()).toBe("secp256k1");
    expect(isEphemeralKeyCompressed()).toBe(false);
    expect(isHkdfKeyCompressed()).toBe(false);
    expect(ephemeralKeySize()).toBe(65);
    expect(symmetricAlgorithm()).toBe("aes-256-gcm");
    expect(symmetricNonceLength()).toBe(16);
  });
});
