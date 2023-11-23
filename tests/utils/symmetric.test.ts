import { concatBytes } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto/utils";

import { ECIES_CONFIG, utils } from "../../src/index";
import { deriveKey } from "../../src/utils";

const { symDecrypt, symEncrypt, decodeHex } = utils;

const TEXT = "helloworld🌍";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

describe("test random symmetric", () => {
  function testRandomKey() {
    const key = randomBytes(32);
    const data = encoder.encode(TEXT);
    expect(data).toEqual(symDecrypt(key, symEncrypt(key, data)));
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

describe("test known symmetric", () => {
  it("tests hkdf", () => {
    const knownKey = Uint8Array.from(
      decodeHex("0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")
    );
    expect(knownKey).toEqual(
      deriveKey(decodeHex("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
    );
  });

  it("tests xchacha20 decrypt", () => {
    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";

    const key = decodeHex(
      "27bd6ec46292a3b421cdaf8a3f0ca759cbc67bcbe7c5855aa0d1e0700fd0e828"
    );
    const nonce = decodeHex("0xfbd5dd10431af533c403d6f4fa629931e5f31872d2f7e7b6");
    const tag = decodeHex("0X5b5ccc27324af03b7ca92dd067ad6eb5");
    const encrypted = decodeHex("aa0664f3c00a09d098bf");
    const data = concatBytes(nonce, tag, encrypted);

    const decrypted = symDecrypt(key, data);
    expect(decoder.decode(decrypted)).toBe("helloworld");

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });
});
