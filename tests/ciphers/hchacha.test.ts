import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, expect, it } from "vitest";

import { _hchacha20, u8, u32 } from "../../src/ciphers/_hchacha.js";

describe("test hchacha20", () => {
  // Test vectors from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-01#section-2.2.1
  it("tests hchacha20 known vector", () => {
    // "expand 32-byte k" in little-endian uint32
    const sigma = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

    const key = hexToBytes(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    const nonce = hexToBytes("000000090000004a0000000031415927");

    const expectedSubkey = hexToBytes(
      "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    );

    const subKey = new Uint32Array(8);
    _hchacha20(sigma, u32(key), u32(nonce), subKey);

    expect(u8(subKey)).toStrictEqual(expectedSubkey);
  });

  it("tests u32 and u8 conversion", () => {
    const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const u32View = u32(original);
    expect(u32View.length).toBe(2);

    const backToU8 = u8(u32View);
    expect(backToU8).toStrictEqual(original);
  });

  it("tests u32 with offset", () => {
    const buffer = new ArrayBuffer(16);
    const view = new Uint8Array(buffer, 4, 8);
    view.set([1, 2, 3, 4, 5, 6, 7, 8]);

    const u32View = u32(view);
    expect(u32View.length).toBe(2);
    expect(u32View.byteOffset).toBe(4);
  });
});
