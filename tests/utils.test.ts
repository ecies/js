import { randomBytes } from "crypto";

import { ECIES_CONFIG } from "../src/config";
import {
  aesDecrypt,
  aesEncrypt,
  decodeHex,
  getValidSecret,
  isValidPrivateKey,
  remove0x,
} from "../src/utils";

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
  it("tests aes with random key", () => {
    const key = randomBytes(32);
    const data = Buffer.from(TEXT);
    expect(data).toEqual(aesDecrypt(key, aesEncrypt(key, data)));
  });

  it("tests aes decrypt with known key", () => {
    const key = Buffer.from(
      decodeHex("0000000000000000000000000000000000000000000000000000000000000000")
    );
    const nonce = Buffer.from(decodeHex("0xf3e1ba810d2c8900b11312b7c725565f"));
    const tag = Buffer.from(decodeHex("0Xec3b71e17c11dbe31484da9450edcf6c"));
    const encrypted = Buffer.from(decodeHex("02d2ffed93b856f148b9"));

    const data = Buffer.concat([nonce, tag, encrypted]);
    const decrypted = aesDecrypt(key, data);
    expect(decrypted.toString()).toBe("helloworld");
  });

  it("tests aes nonce length config", () => {
    ECIES_CONFIG.symmetricNonceLength = 12;

    const key = randomBytes(32);
    const data = Buffer.from(TEXT);
    expect(data.equals(aesDecrypt(key, aesEncrypt(key, data)))).toBe(true);

    ECIES_CONFIG.symmetricNonceLength = 16;
  });
});
