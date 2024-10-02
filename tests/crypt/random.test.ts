import { bytesToHex } from "@noble/ciphers/utils";
import { ECIES_CONFIG, PrivateKey, decrypt, encrypt } from "../../src";

const TEXT = "helloworld🌍";
const encoder = new TextEncoder();

describe("test random encrypt and decrypt", () => {
  function checkCompressed(sk: PrivateKey) {
    const encrypted = encrypt(sk.publicKey.compressed, encoder.encode(TEXT));
    expect(decrypt(sk.secret, encrypted).toString()).toStrictEqual(TEXT);
  }

  function checkUncompressed(sk: PrivateKey) {
    const encrypted = encrypt(sk.publicKey.uncompressed, encoder.encode(TEXT));
    expect(decrypt(sk.secret, encrypted).toString()).toStrictEqual(TEXT);
  }

  function checkHex(sk: PrivateKey) {
    const encrypted = encrypt(sk.publicKey.toHex(), encoder.encode(TEXT));
    expect(decrypt(bytesToHex(sk.secret), encrypted).toString()).toStrictEqual(TEXT);
  }

  function testRandom() {
    const sk1 = new PrivateKey();
    const sk2 = new PrivateKey();

    checkCompressed(sk1);
    checkUncompressed(sk2);
    checkHex(sk1);
  }

  it("tests default", () => {
    testRandom();
  });

  it("tests compressed ephemeral key", () => {
    ECIES_CONFIG.isEphemeralKeyCompressed = true;

    testRandom();

    ECIES_CONFIG.isEphemeralKeyCompressed = false;
  });

  it("tests compressed hkdf key", () => {
    ECIES_CONFIG.isHkdfKeyCompressed = true;

    testRandom();

    ECIES_CONFIG.isHkdfKeyCompressed = false;
  });

  it("tests 12 bytes nonce", () => {
    ECIES_CONFIG.symmetricNonceLength = 12;

    testRandom();

    ECIES_CONFIG.symmetricNonceLength = 16;
  });

  it("tests compressed ephemeral and hkdf key with 12 bytes nonce", () => {
    ECIES_CONFIG.isEphemeralKeyCompressed = true;
    ECIES_CONFIG.isHkdfKeyCompressed = true;
    ECIES_CONFIG.symmetricNonceLength = 12;

    testRandom();

    ECIES_CONFIG.isEphemeralKeyCompressed = false;
    ECIES_CONFIG.isHkdfKeyCompressed = false;
    ECIES_CONFIG.symmetricNonceLength = 16;
  });

  it("tests compressed ephemeral key and chacha", () => {
    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";
    ECIES_CONFIG.isEphemeralKeyCompressed = true;

    testRandom();

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
    ECIES_CONFIG.isEphemeralKeyCompressed = false;
  });

  it("tests curve25519 and chacha", () => {
    ECIES_CONFIG.ellipticCurve = "x25519";
    testRandom();

    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";
    testRandom();

    ECIES_CONFIG.ellipticCurve = "ed25519";
    testRandom();

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
    ECIES_CONFIG.ellipticCurve = "secp256k1";
  });

  it("tests aes256cbc", () => {
    ECIES_CONFIG.symmetricAlgorithm = "aes-256-cbc";

    testRandom();

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });
});
