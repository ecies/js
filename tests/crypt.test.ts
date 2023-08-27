import {
  ECIES_CONFIG,
  PrivateKey,
  PublicKey,
  decrypt,
  encrypt,
  utils,
} from "../src/index";

const decodeHex = utils.decodeHex;

const TEXT = "helloworld🌍";

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

describe("test encrypt and decrypt", () => {
  it("tests encrypt/decrypt", () => {
    const sk1 = new PrivateKey();
    check(sk1);
    checkHex(sk1);

    const sk2 = new PrivateKey();
    check(sk2, true);
    checkHex(sk2);
  });

  it("tests known sk pk", () => {
    const sk = PrivateKey.fromHex(
      "5b5b1a0ff51e4350badd6f58d9e6fa6f57fbdbde6079d12901770dda3b803081"
    );
    const pk = PublicKey.fromHex(
      "048e41409f2e109f2d704f0afd15d1ab53935fd443729913a7e8536b4cef8cf5773d4db7bbd99e9ed64595e24a251c9836f35d4c9842132443c17f6d501b3410d2"
    );
    const enc = encrypt(pk.toHex(), Buffer.from(TEXT));
    expect(decrypt(sk.toHex(), enc).toString()).toBe(TEXT);
  });

  it("tests config can be changed", () => {
    ECIES_CONFIG.isEphemeralKeyCompressed = true;
    ECIES_CONFIG.isHkdfKeyCompressed = true;
    ECIES_CONFIG.symmetricNonceLength = 12;

    const sk1 = new PrivateKey();
    check(sk1);

    const sk2 = new PrivateKey();
    checkHex(sk2);

    ECIES_CONFIG.isEphemeralKeyCompressed = false;
    ECIES_CONFIG.isHkdfKeyCompressed = false;
    ECIES_CONFIG.symmetricNonceLength = 16;
  });

  it("tests encrypt/decrypt chacha", () => {
    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";
    ECIES_CONFIG.isEphemeralKeyCompressed = true;

    const sk1 = new PrivateKey();
    check(sk1);

    const sk2 = new PrivateKey();
    checkHex(sk2);

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
    ECIES_CONFIG.isEphemeralKeyCompressed = false;
  });

  it("tests known sk pk chacha", () => {
    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";

    const sk = PrivateKey.fromHex(
      "0000000000000000000000000000000000000000000000000000000000000002"
    );
    const pk = PublicKey.fromHex(
      "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    );
    const enc = encrypt(pk.toHex(), Buffer.from(TEXT));
    expect(decrypt(sk.toHex(), enc).toString()).toBe(TEXT);

    const known = Buffer.from(
      decodeHex(
        "0x04e314abc14398e07974cd50221b682ed5f0629e977345fc03e2047208ee6e279f" +
          "fb2a6942878d3798c968d89e59c999e082b0598d1b641968c48c8d47c570210d0a" +
          "b1ade95eeca1080c45366562f9983faa423ee3fd3260757053d5843c5f453e1ee6" +
          "bb955c8e5d4aee8572139357a091909357a8931b"
      )
    );
    expect(decrypt(sk.toHex(), known).toString()).toBe(TEXT);

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });
});
