import { bytesToHex } from "@noble/ciphers/utils";
import { describe, expect, it } from "vitest";

import { decrypt, encrypt, PrivateKey } from "../../src";
import { Config, type EllipticCurve } from "../../src/config";

const encoder = new TextEncoder();
const TEXT = encoder.encode("hello world🌍");

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

describe.each(params)("test random encrypt/decrypt on curve: $curve", ({
  curve,
  isEphemeralKeyCompressed,
  isHkdfKeyCompressed,
}) => {
  let caseSuffix = "";
  if (curve === "secp256k1") {
    caseSuffix = ` isEphemeralKeyCompressed: ${isEphemeralKeyCompressed} isHkdfKeyCompressed: ${isHkdfKeyCompressed}`;
  }

  it("tests aes-256-gcm (16 bytes nonce)" + caseSuffix, () => {
    const config = getConfig(curve, isEphemeralKeyCompressed, isHkdfKeyCompressed);
    testRandom(config);
  });

  it("tests aes-256-gcm (12 bytes nonce)" + caseSuffix, () => {
    const config = getConfig(curve, isEphemeralKeyCompressed, isHkdfKeyCompressed);
    config.symmetricNonceLength = 12;
    testRandom(config);
  });

  it("tests xchacha20" + caseSuffix, () => {
    const config = getConfig(curve, isEphemeralKeyCompressed, isHkdfKeyCompressed);
    config.symmetricAlgorithm = "xchacha20";
    testRandom(config);
  });
});

function checkCompressed(sk: PrivateKey, config: Config) {
  const encrypted = encrypt(sk.publicKey.toBytes(), TEXT, config);
  expect(decrypt(sk.secret, encrypted, config)).toStrictEqual(TEXT);
}

function checkUncompressed(sk: PrivateKey, config: Config) {
  const encrypted = encrypt(sk.publicKey.toBytes(false), TEXT, config);
  expect(decrypt(sk.secret, encrypted, config)).toStrictEqual(TEXT);
}

function checkHex(sk: PrivateKey, config: Config) {
  const encrypted = encrypt(sk.publicKey.toHex(), TEXT, config);
  expect(decrypt(bytesToHex(sk.secret), encrypted, config)).toStrictEqual(TEXT);
}

function testRandom(config: Config) {
  const sk1 = new PrivateKey(undefined, config.ellipticCurve);
  const sk2 = new PrivateKey(undefined, config.ellipticCurve);

  checkCompressed(sk1, config);
  checkUncompressed(sk2, config);
  checkHex(sk1, config);
}

function getConfig(
  curve: EllipticCurve,
  isEphemeralKeyCompressed: boolean,
  isHkdfKeyCompressed: boolean
): Config {
  const config = new Config();
  config.ellipticCurve = curve;

  if (config.ellipticCurve === "secp256k1") {
    config.isEphemeralKeyCompressed = isEphemeralKeyCompressed;
    config.isHkdfKeyCompressed = isHkdfKeyCompressed;
  }
  return config;
}
