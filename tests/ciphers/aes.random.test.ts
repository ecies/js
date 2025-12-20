import { randomBytes } from "@noble/ciphers/utils.js";
import { describe, it } from "vitest";

import {
  aes256cbc as _aes256cbc,
  aes256gcm as _aes256gcm,
} from "../../src/ciphers/aes.noble.js";
import { aes256cbc, aes256gcm } from "../../src/ciphers/aes.node.js";
import { hello, testRandom } from "./common.js";

describe("test aes random", () => {
  function testGcm(nonceLength: number, aad?: Uint8Array) {
    const key = randomBytes(32);
    const nonce = randomBytes(nonceLength);
    const noble = _aes256gcm(key, nonce, aad);
    const compat = aes256gcm(key, nonce, aad);
    testRandom(hello, noble, compat);
  }

  function testCbc() {
    const key = randomBytes(32);
    const nonce = randomBytes(16);
    const noble = _aes256cbc(key, nonce);
    const compat = aes256cbc(key, nonce);
    testRandom(hello, noble, compat);
  }

  it("tests gcm 16 bytes nonce", () => {
    testGcm(16);
    testGcm(16, randomBytes(8));
    testGcm(16, randomBytes(16));
  });

  it("tests gcm 12 bytes nonce", () => {
    testGcm(12);
    testGcm(12, randomBytes(8));
    testGcm(12, randomBytes(16));
  });

  it("tests cbc", () => {
    testCbc();
  });
});
