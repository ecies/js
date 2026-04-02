import { describe, expect, it } from "vitest";

import { decrypt, encrypt } from "../../src";
import { Config } from "../../src/config";
import { decodeHex } from "../../src/utils";

const TEXT = "helloworld🌍";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

describe("test known encrypt and decrypt", () => {
  function testDecrypt(sk: string, data: string, expected: Uint8Array, config: Config) {
    const decrypted = decrypt(sk, expected, config);
    expect(decoder.decode(decrypted)).toBe(data);
  }

  function testEncryptDecrypt(sk: string, pk: string, data: string, config: Config) {
    const encrypted = encrypt(pk, encoder.encode(data), config);
    testDecrypt(sk, data, encrypted, config);
  }

  function testDecryptKnown(
    sk: string,
    pk: string,
    data: string,
    encrypted: Uint8Array,
    config: Config
  ) {
    // it should not be equal due to ephemeral key
    const _encrypted = encrypt(pk, encoder.encode(data), config);
    expect(_encrypted).not.toStrictEqual(encrypted);
    testDecrypt(sk, data, encrypted, config);
  }

  it("tests secp256k1: aes", () => {
    const sk = "5b5b1a0ff51e4350badd6f58d9e6fa6f57fbdbde6079d12901770dda3b803081";
    const pk =
      "048e41409f2e109f2d704f0afd15d1ab53935fd443729913a7e8536b4cef8cf5773d4db7bbd99e9ed64595e24a251c9836f35d4c9842132443c17f6d501b3410d2";

    testEncryptDecrypt(sk, pk, TEXT, new Config());
  });

  it("tests secp256k1: chacha", () => {
    const config = new Config();
    config.symmetricAlgorithm = "xchacha20";

    const sk = "0000000000000000000000000000000000000000000000000000000000000002";
    const pk = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    testEncryptDecrypt(sk, pk, TEXT, config);

    const encrypted = decodeHex(
      "0x04e314abc14398e07974cd50221b682ed5f0629e977345fc03e2047208ee6e279f" +
        "fb2a6942878d3798c968d89e59c999e082b0598d1b641968c48c8d47c570210d0a" +
        "b1ade95eeca1080c45366562f9983faa423ee3fd3260757053d5843c5f453e1ee6" +
        "bb955c8e5d4aee8572139357a091909357a8931b"
    );
    testDecryptKnown(sk, pk, TEXT, encrypted, config);
  });

  it("tests x25519: aes", () => {
    const config = new Config();
    config.ellipticCurve = "x25519";

    const sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const pk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    testEncryptDecrypt(sk, pk, TEXT, config);
  });

  it("tests x25519: chacha", () => {
    const config = new Config();
    config.ellipticCurve = "x25519";
    config.symmetricAlgorithm = "xchacha20";

    const sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const pk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    testEncryptDecrypt(sk, pk, TEXT, config);

    const encrypted = decodeHex(
      "cfff9c146116355d0e7ce81df984b4d64c5e5c9c055fbfda0ff8169e11d05e12ed" +
        "f025069032adf3e16b763d886f3812bc8f1902fd29204ed3b6a2ea4e52a01dc440" +
        "72ed1635aefbad1571bd5b972a7304ba25301f12"
    );
    testDecryptKnown(sk, pk, TEXT, encrypted, config);
  });

  it("tests ed25519: aes", () => {
    const config = new Config();
    config.ellipticCurve = "ed25519";

    const sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    testEncryptDecrypt(sk, pk, TEXT, config);
  });

  it("tests ed25519: chacha", () => {
    const config = new Config();
    config.ellipticCurve = "ed25519";
    config.symmetricAlgorithm = "xchacha20";

    const sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const encrypted = decodeHex(
      "329c94d4f7b282e885626302c1383a4f60a0d1ad34ca46b6c0d128404376afb5cf" +
        "6d42a1f70997f4f2af4926e278259fb5b67ac9c30b5e50a311d4a890378926881d" +
        "f1d3e0556c99ff7e0ed8b0d14f1e9536c83a282f"
    );
    testDecryptKnown(sk, pk, TEXT, encrypted, config);
  });
});
