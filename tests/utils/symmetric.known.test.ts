import { describe, expect, it } from "vitest";

import { concatBytes } from "@noble/ciphers/utils";

import { ECIES_CONFIG } from "../../src";
import { decodeHex, symDecrypt } from "../../src/utils";

// from https://github.com/C2SP/wycheproof/tree/master/testvectors
describe("test known symmetric", () => {
  it("tests aes gcm 16 bytes nonce", () => {
    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";

    testKnown(
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "28e1c5232f4ee8161dbe4c036309e0b3254e9212bef0a93431ce5e5604c8f6a73c18a3183018b770",
      "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
      "5c2ea9b695fcf6e264b96074d6bfa572",
      "d5808a1bd11a01129bf3c6919aff2339"
    );
  });

  it("tests aes gcm 12 bytes nonce", () => {
    ECIES_CONFIG.symmetricNonceLength = 12;
    testKnown(
      "2a",
      "06",
      "cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273",
      "99e23ec48985bccdeeab60f1",
      "633c1e9703ef744ffffb40edf9d14355"
    );

    testKnown(
      "00010203040506070809",
      "e27abdd2d2a53d2f136b",
      "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20",
      "00112233445566778899aabb",
      "9a4a2579529301bcfb71c78d4060f52c",
      "00000000ffffffff"
    );
    ECIES_CONFIG.symmetricNonceLength = 16;
  });

  it("tests aes cbc", () => {
    ECIES_CONFIG.symmetricAlgorithm = "aes-256-cbc";
    testKnown(
      "",
      "e7c166554d1bb32792c981fa674cc4d8",
      "7bf9e536b66a215c22233fe2daaa743a898b9acb9f7802de70b40e3d6e43ef97",
      "eb38ef61717e1324ae064e86f1c3e797"
    );
    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });

  it("tests xchacha20", () => {
    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";
    testKnown(
      "68656c6c6f776f726c64", // "helloworld"
      "aa0664f3c00a09d098bf",
      "27bd6ec46292a3b421cdaf8a3f0ca759cbc67bcbe7c5855aa0d1e0700fd0e828",
      "0xfbd5dd10431af533c403d6f4fa629931e5f31872d2f7e7b6",
      "0X5b5ccc27324af03b7ca92dd067ad6eb5"
    );

    testKnown(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
      "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
      "404142434445464748494a4b4c4d4e4f5051525354555657",
      "c0875924c1c7987947deafd8780acf49",
      "50515253c0c1c2c3c4c5c6c7"
    );

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });
});

function testKnown(
  _plainText: string,
  _cipherText: string,
  _key: string,
  _nonce: string,
  _tag: string = "",
  _aad: string = ""
) {
  const key = decodeHex(_key);
  const nonce = decodeHex(_nonce);
  const tag = decodeHex(_tag);
  const cipherText = decodeHex(_cipherText);
  const data = concatBytes(nonce, tag, cipherText);

  const plainText = decodeHex(_plainText);
  const aad = decodeHex(_aad);
  expect(symDecrypt(key, data, aad)).toStrictEqual(plainText);
}
