import { describe, expect, it } from "vitest";

import { randomBytes } from "@noble/ciphers/webcrypto";
import { ECIES_CONFIG } from "../../src";
import { decodeHex, symDecrypt, symEncrypt } from "../../src/utils";

const TEXT = "helloworld🌍";
const encoder = new TextEncoder();

describe("test random symmetric", () => {
  function testRandomKey() {
    const key = randomBytes(32);
    const data = encoder.encode(TEXT);
    expect(data).toStrictEqual(symDecrypt(key, symEncrypt(key, data)));
  }

  it("tests aes", () => {
    testRandomKey();
  });

  it("tests aes nonce length config", () => {
    ECIES_CONFIG.symmetricNonceLength = 12;

    testRandomKey();

    ECIES_CONFIG.symmetricNonceLength = 16;
  });

  it("tests xchacha20", () => {
    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";

    testRandomKey();

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });

  it("tests not implemented", () => {
    ECIES_CONFIG.symmetricAlgorithm = "" as any;

    expect(testRandomKey).toThrow("Not implemented");

    expect(() => symDecrypt(randomBytes(32), decodeHex("01010e0e"))).toThrow(
      "Not implemented"
    );

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });
});
