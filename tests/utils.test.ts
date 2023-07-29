import { randomBytes } from "crypto";
import { ECIES_CONFIG, utils } from "../src/index";
import { deriveKey, isValidPrivateKey } from "../src/utils";

const { aesDecrypt, aesEncrypt, decodeHex, getValidSecret, remove0x } = utils;

const TEXT = "helloworld🌍";

describe("test hex utils", () => {
  it("should remove 0x", () => {
    expect(remove0x("0011")).toBe("0011");
    expect(remove0x("0022")).toBe("0022");
    expect(remove0x("0x0011")).toBe("0011");
    expect(remove0x("0X0022")).toBe("0022");
  });

  it("should convert hex to buffer", () => {
    const decoded = decodeHex("0x0011");
    expect(decoded).toEqual(Buffer.from([0, 0x11]));
  });
});

describe("test elliptic utils", () => {
  it("should generate valid secret", () => {
    const key = getValidSecret();
    expect(isValidPrivateKey(key)).toBe(true);
  });
});

describe("test symmetric utils", () => {
  function testRandomKey() {
    const key = randomBytes(32);
    const data = Buffer.from(TEXT);
    expect(data).toEqual(aesDecrypt(key, aesEncrypt(key, data)));
  }

  it("tests hkdf with know key", () => {
    const knownKey = decodeHex(
      "0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
    );
    expect(knownKey).toEqual(
      deriveKey(decodeHex("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
    );
  });

  it("tests aes with random key", () => {
    testRandomKey();
  });

  it("tests aes decrypt with known key", () => {
    const key = decodeHex(
      "0000000000000000000000000000000000000000000000000000000000000000"
    );
    const nonce = decodeHex("0xf3e1ba810d2c8900b11312b7c725565f");
    const tag = decodeHex("0Xec3b71e17c11dbe31484da9450edcf6c");
    const encrypted = decodeHex("02d2ffed93b856f148b9");

    const data = Buffer.concat([nonce, tag, encrypted]);
    const decrypted = aesDecrypt(key, data);
    expect(decrypted.toString()).toBe("helloworld");
  });

  it("tests aes nonce length config", () => {
    ECIES_CONFIG.symmetricNonceLength = 12;

    testRandomKey();

    ECIES_CONFIG.symmetricNonceLength = 16;
  });

  it("tests xchacha20 decrypt with known key", () => {
    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";

    const key = decodeHex(
      "27bd6ec46292a3b421cdaf8a3f0ca759cbc67bcbe7c5855aa0d1e0700fd0e828"
    );
    const nonce = decodeHex("0xfbd5dd10431af533c403d6f4fa629931e5f31872d2f7e7b6");
    const tag = decodeHex("0X5b5ccc27324af03b7ca92dd067ad6eb5");
    const encrypted = decodeHex("aa0664f3c00a09d098bf");
    const data = Buffer.concat([nonce, tag, encrypted]);

    const decrypted = aesDecrypt(key, data);
    expect(decrypted.toString()).toBe("helloworld");

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });

  it("tests xchacha20 with random key", () => {
    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";

    testRandomKey();

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });

  it("tests not implemented", () => {
    ECIES_CONFIG.symmetricAlgorithm = "" as any;

    expect(testRandomKey).toThrow("Not implemented");

    expect(() => aesDecrypt(randomBytes(32), decodeHex("01010e0e"))).toThrow(
      "Not implemented"
    );

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });
});
