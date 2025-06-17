import { bytesToHex } from "@noble/ciphers/utils";
import { describe, expect, it } from "vitest";

import {
  decrypt as _decrypt,
  encrypt as _encrypt,
  ECIES_CONFIG,
  PrivateKey,
} from "../../src";
import type { EllipticCurve } from "../../src/config";

const encoder = new TextEncoder();
const TEXT = encoder.encode("hello world🌍");
const decrypt = (sk: Buffer | string, data: Uint8Array) =>
  Uint8Array.from(_decrypt(sk, data));
const encrypt = (pk: Uint8Array | string, data: Uint8Array) =>
  Uint8Array.from(_encrypt(pk, data));

interface TestParameter {
  curve: EllipticCurve;
  isEphemeralKeyCompressed: boolean;
  isHkdfKeyCompressed: boolean;
}

const params: TestParameter[] = [
  { curve: "secp256k1", isEphemeralKeyCompressed: false, isHkdfKeyCompressed: false },
  { curve: "secp256k1", isEphemeralKeyCompressed: false, isHkdfKeyCompressed: true },
  { curve: "secp256k1", isEphemeralKeyCompressed: true, isHkdfKeyCompressed: false },
  { curve: "secp256k1", isEphemeralKeyCompressed: true, isHkdfKeyCompressed: true },
  { curve: "x25519", isEphemeralKeyCompressed: false, isHkdfKeyCompressed: false },
  { curve: "ed25519", isEphemeralKeyCompressed: false, isHkdfKeyCompressed: false },
];

describe.each(params)(
  "test random encrypt/decrypt on curve: $curve",
  ({ curve, isEphemeralKeyCompressed, isHkdfKeyCompressed }) => {
    ECIES_CONFIG.ellipticCurve = curve;

    let caseSuffix = "";
    if (ECIES_CONFIG.ellipticCurve === "secp256k1") {
      ECIES_CONFIG.isEphemeralKeyCompressed = isEphemeralKeyCompressed;
      ECIES_CONFIG.isHkdfKeyCompressed = isHkdfKeyCompressed;
      caseSuffix = ` isEphemeralKeyCompressed: ${isEphemeralKeyCompressed} isHkdfKeyCompressed: ${isHkdfKeyCompressed}`;
    }

    it("tests aes-256-gcm (16 bytes nonce)" + caseSuffix, () => {
      testRandom();
    });

    it("tests aes-256-gcm (12 bytes nonce)" + caseSuffix, () => {
      ECIES_CONFIG.symmetricNonceLength = 12;
      testRandom();
      ECIES_CONFIG.symmetricNonceLength = 16;
    });

    it("tests aes256cbc" + caseSuffix, () => {
      ECIES_CONFIG.symmetricAlgorithm = "aes-256-cbc";
      testRandom();
      ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
    });

    it("tests xchacha20" + caseSuffix, () => {
      ECIES_CONFIG.symmetricAlgorithm = "xchacha20";
      testRandom();
      ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
    });
  }
);

function checkCompressed(sk: PrivateKey) {
  const encrypted = encrypt(sk.publicKey.toBytes(), TEXT);
  expect(decrypt(sk.secret, encrypted)).toStrictEqual(TEXT);
}

function checkUncompressed(sk: PrivateKey) {
  const encrypted = encrypt(sk.publicKey.toBytes(false), TEXT);
  expect(decrypt(sk.secret, encrypted)).toStrictEqual(TEXT);
}

function checkHex(sk: PrivateKey) {
  const encrypted = encrypt(sk.publicKey.toHex(), TEXT);
  expect(decrypt(bytesToHex(sk.secret), encrypted)).toStrictEqual(TEXT);
}

function testRandom() {
  const sk1 = new PrivateKey();
  const sk2 = new PrivateKey();

  checkCompressed(sk1);
  checkUncompressed(sk2);
  checkHex(sk1);
}
