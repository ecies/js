import { describe, expect, it } from "vitest";

import { concatBytes } from "@noble/ciphers/utils";

import { ECIES_CONFIG } from "../../src";
import { decodeHex, symDecrypt } from "../../src/utils";

const decoder = new TextDecoder();

describe("test known symmetric", () => {
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
