import { randomBytes } from "@noble/ciphers/webcrypto";
import { describe, expect, it } from "vitest";
import { ECIES_CONFIG } from "../../src";
import { symDecrypt, symEncrypt } from "../../src/utils";

const TEXT = "hello world🌍";
const encoder = new TextEncoder();

describe("test random symmetric", () => {
  function testRandomKey() {
    const key = randomBytes(32);
    const data = encoder.encode(TEXT);
    expect(data).toStrictEqual(symDecrypt(key, symEncrypt(key, data)));

    const aad = randomBytes(8);
    expect(data).toStrictEqual(symDecrypt(key, symEncrypt(key, data, aad), aad));
  }

  it("tests aes gcm 16 bytes nonce", () => {
    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
    testRandomKey();
  });

  it("tests aes gcm 12 bytes nonce", () => {
    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
    ECIES_CONFIG.symmetricNonceLength = 12;
    testRandomKey();
    ECIES_CONFIG.symmetricNonceLength = 16;
  });

  it("tests aes cbc", () => {
    ECIES_CONFIG.symmetricAlgorithm = "aes-256-cbc";
    testRandomKey();
  });

  it("tests xchacha20", () => {
    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";
    testRandomKey();
  });

  it("tests not implemented", () => {
    // @ts-expect-error
    ECIES_CONFIG.symmetricAlgorithm = "";
    expect(testRandomKey).toThrow("Not implemented");
    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });
});
