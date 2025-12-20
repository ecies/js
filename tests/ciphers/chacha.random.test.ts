import { randomBytes } from "@noble/ciphers/utils.js";
import { describe, expect, it } from "vitest";

import {
  chacha20 as _chacha20,
  xchacha20 as _xchacha20,
} from "../../src/ciphers/chacha.noble.js";
import { chacha20, xchacha20 } from "../../src/ciphers/chacha.node.js";
import { hello, testRandom } from "./common.js";

describe("test chacha random", () => {
  function test(
    nobleFunc: typeof _chacha20 | typeof _xchacha20,
    compatFunc: typeof chacha20 | typeof xchacha20,
    nonceLength: number,
    aad?: Uint8Array
  ) {
    const key = randomBytes(32);
    const nonce = randomBytes(nonceLength);
    const noble = nobleFunc(key, nonce, aad);
    const compat = compatFunc(key, nonce, aad);
    testRandom(hello, noble, compat);
  }

  function testError(
    compatFunc: typeof chacha20 | typeof xchacha20,
    nonceLength: number,
    expectedError: string
  ) {
    const key = randomBytes(32);
    const nonce = randomBytes(nonceLength);
    expect(() => compatFunc(key, nonce)).toThrowError(expectedError);
  }

  function testChacha20(aad?: Uint8Array) {
    test(_chacha20, chacha20, 12, aad);
  }

  function testXChacha20(aad?: Uint8Array) {
    test(_xchacha20, xchacha20, 24, aad);
  }

  it("tests chacha20", () => {
    testChacha20();
    testChacha20(randomBytes(8));
    testChacha20(randomBytes(16));

    testError(chacha20, 24, "chacha20's nonce must be 12 bytes");
  });

  it("tests xchacha20", () => {
    testXChacha20();
    testXChacha20(randomBytes(8));
    testXChacha20(randomBytes(16));

    testError(xchacha20, 12, "xchacha20's nonce must be 24 bytes");
  });
});
