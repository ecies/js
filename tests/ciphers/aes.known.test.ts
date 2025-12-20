import { concatBytes, hexToBytes } from "@noble/ciphers/utils.js";
import { describe, expect, it } from "vitest";

import {
  aes256cbc as _aes256cbc,
  aes256gcm as _aes256gcm,
} from "../../src/ciphers/aes.noble.js";
import { aes256cbc, aes256gcm } from "../../src/ciphers/aes.node.js";
import { testKnown } from "./common.js";

// from https://github.com/C2SP/wycheproof/tree/master/testvectors
describe("test aes known", () => {
  it("tests gcm 12 bytes nonce", () => {
    const key = hexToBytes(
      "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20"
    );
    const nonce = hexToBytes("00112233445566778899aabb");
    const aad = hexToBytes("00000000ffffffff");
    const noble = _aes256gcm(key, nonce, aad);
    const compat = aes256gcm(key, nonce, aad);

    const cipherText = hexToBytes("e27abdd2d2a53d2f136b");
    const tag = hexToBytes("9a4a2579529301bcfb71c78d4060f52c");
    const encrypted = concatBytes(cipherText, tag);

    const plainText = hexToBytes("00010203040506070809");

    testKnown(plainText, encrypted, noble, compat);
  });

  it("tests gcm 16 bytes nonce", () => {
    // Test with 16 byte nonce - just verify noble and compat produce same results
    const key = hexToBytes(
      "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20"
    );
    const nonce = hexToBytes("00112233445566778899aabbccddeeff");
    const aad = hexToBytes("00000000ffffffff");
    const noble = _aes256gcm(key, nonce, aad);
    const compat = aes256gcm(key, nonce, aad);

    const plainText = hexToBytes("00010203040506070809");

    // Encrypt with noble and verify compat can decrypt
    const encrypted = noble.encrypt(plainText);
    expect(compat.decrypt(encrypted)).toStrictEqual(plainText);

    // Encrypt with compat and verify noble can decrypt
    const compatEncrypted = compat.encrypt(plainText);
    expect(noble.decrypt(compatEncrypted)).toStrictEqual(plainText);

    // Both should produce identical ciphertext
    expect(encrypted).toStrictEqual(compatEncrypted);
  });

  it("tests cbc", () => {
    const key = hexToBytes(
      "7bf9e536b66a215c22233fe2daaa743a898b9acb9f7802de70b40e3d6e43ef97"
    );
    const nonce = hexToBytes("eb38ef61717e1324ae064e86f1c3e797");
    const noble = _aes256cbc(key, nonce);
    const compat = aes256cbc(key, nonce);

    const cipherText = hexToBytes("e7c166554d1bb32792c981fa674cc4d8");
    const plainText = Uint8Array.from([]);

    testKnown(plainText, cipherText, noble, compat);
  });
});
