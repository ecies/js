import { ECIES_CONFIG, PrivateKey, decrypt, encrypt } from "../../src/index";

const TEXT = "helloworld🌍";

describe("test random encrypt and decrypt", () => {
  function check(sk: PrivateKey, compressed: boolean = false) {
    if (compressed) {
      const encrypted = encrypt(sk.publicKey.compressed, Buffer.from(TEXT));
      expect(decrypt(sk.secret, encrypted).toString()).toBe(TEXT);
    } else {
      const encrypted = encrypt(sk.publicKey.uncompressed, Buffer.from(TEXT));
      expect(decrypt(sk.secret, encrypted).toString()).toBe(TEXT);
    }
  }

  function checkHex(sk: PrivateKey) {
    const encrypted = encrypt(sk.publicKey.toHex(), Buffer.from(TEXT));
    expect(decrypt(sk.secret, encrypted).toString()).toBe(TEXT);
  }

  function testRandom() {
    const sk1 = new PrivateKey();
    check(sk1);
    checkHex(sk1);

    const sk2 = new PrivateKey();
    check(sk2, true);
    checkHex(sk2);
  }

  it("tests default", () => {
    testRandom();
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
