import { describe, expect, it } from "vitest";

import { decrypt, ECIES_CONFIG, encrypt } from "../../src";
import { decodeHex } from "../../src/utils";

const TEXT = "helloworld🌍";
const encoder = new TextEncoder();

describe("test known encrypt and decrypt", () => {
  function testDecrypt(sk: string, data: string, expected: Uint8Array) {
    expect(decrypt(sk, expected).toString()).toBe(data);
  }

  function testEncryptDecrypt(sk: string, pk: string, data: string) {
    testDecrypt(sk, data, encrypt(pk, encoder.encode(data)));
  }

  function testDecryptKnown(sk: string, pk: string, data: string, encrypted: Uint8Array) {
    // it should not be equal due to ephemeral key
    expect(encrypted).not.toStrictEqual(encrypt(pk, encoder.encode(data)));
    testDecrypt(sk, data, encrypted);
  }

  it("tests default", () => {
    const sk = "5b5b1a0ff51e4350badd6f58d9e6fa6f57fbdbde6079d12901770dda3b803081";
    const pk =
      "048e41409f2e109f2d704f0afd15d1ab53935fd443729913a7e8536b4cef8cf5773d4db7bbd99e9ed64595e24a251c9836f35d4c9842132443c17f6d501b3410d2";

    testEncryptDecrypt(sk, pk, TEXT);
  });

  it("tests chacha", () => {
    ECIES_CONFIG.symmetricAlgorithm = "xchacha20";

    const sk = "0000000000000000000000000000000000000000000000000000000000000002";
    const pk = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    testEncryptDecrypt(sk, pk, TEXT);

    const encrypted = decodeHex(
      "0x04e314abc14398e07974cd50221b682ed5f0629e977345fc03e2047208ee6e279f" +
        "fb2a6942878d3798c968d89e59c999e082b0598d1b641968c48c8d47c570210d0a" +
        "b1ade95eeca1080c45366562f9983faa423ee3fd3260757053d5843c5f453e1ee6" +
        "bb955c8e5d4aee8572139357a091909357a8931b"
    );
    testDecryptKnown(sk, pk, TEXT, encrypted);

    ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm";
  });

  it("tests x25519", () => {
    ECIES_CONFIG.ellipticCurve = "x25519";

    const sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const pk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    testEncryptDecrypt(sk, pk, TEXT);

    ECIES_CONFIG.ellipticCurve = "secp256k1";
  });

  it("tests ed25519", () => {
    ECIES_CONFIG.ellipticCurve = "ed25519";

    const sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    testEncryptDecrypt(sk, pk, TEXT);

    ECIES_CONFIG.ellipticCurve = "secp256k1";
  });
});
