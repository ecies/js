import { concatBytes, hexToBytes } from "@noble/ciphers/utils.js";
import { describe, it } from "vitest";

import {
  chacha20 as _chacha20,
  xchacha20 as _xchacha20,
} from "../../src/ciphers/chacha.noble.js";
import { chacha20, xchacha20 } from "../../src/ciphers/chacha.node.js";
import { testKnown } from "./common.js";

describe("test chacha known", () => {
  function test(
    nobleFunc: typeof _chacha20 | typeof _xchacha20,
    compatFunc: typeof chacha20 | typeof xchacha20,
    key: string,
    nonce: string,
    aad: string,
    plainText: string,
    cipherText: string,
    tag: string
  ) {
    const _key = hexToBytes(key);
    const _nonce = hexToBytes(nonce);
    const _aad = hexToBytes(aad);
    const _noble = nobleFunc(_key, _nonce, _aad);
    const _compat = compatFunc(_key, _nonce, _aad);
    const _plainText = hexToBytes(plainText);
    const _cipherText = hexToBytes(cipherText);
    const _tag = hexToBytes(tag);
    testKnown(_plainText, concatBytes(_cipherText, _tag), _noble, _compat);
  }

  const plainText =
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";

  it("tests chacha20", () => {
    // https://datatracker.ietf.org/doc/html/draft-nir-cfrg-chacha20-poly1305#section-2.8.1
    const key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const nonce = "070000004041424344454647";
    const aad = "50515253c0c1c2c3c4c5c6c7";

    const cipherText =
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    const tag = "1ae10b594f09e26a7e902ecbd0600691";

    test(_chacha20, chacha20, key, nonce, aad, plainText, cipherText, tag);
  });

  it("tests xchacha20", () => {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-01#appendix-A.3.1
    const key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const nonce = "404142434445464748494a4b4c4d4e4f5051525354555657";
    const aad = "50515253c0c1c2c3c4c5c6c7";

    const cipherText =
      "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e";
    const tag = "c0875924c1c7987947deafd8780acf49";

    test(_xchacha20, xchacha20, key, nonce, aad, plainText, cipherText, tag);
  });
});
