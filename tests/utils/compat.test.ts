import { concatBytes } from "@noble/ciphers/utils";
import { aes_256_gcm as aes } from "@noble/ciphers/webcrypto/aes";
import { randomBytes } from "@noble/ciphers/webcrypto/utils";

import { decodeHex } from "../../src/utils";
import { aes256gcm } from "../../src/utils/compat";

const TEXT = "helloworld🌍";
const encoder = new TextEncoder();

describe("test random compat", () => {
  const msg = encoder.encode(TEXT);

  async function testRandom(aad?: Uint8Array) {
    const key = randomBytes();
    const nonce = randomBytes(16);
    const noble = aes(key, nonce, aad);
    const compat = aes256gcm(key, nonce, aad);
    // same encryption
    expect(await noble.encrypt(msg)).toStrictEqual(compat.encrypt(msg));
    // noble encrypts, compat decrypts
    expect(compat.decrypt(await noble.encrypt(msg))).toStrictEqual(msg);
    // noble decrypts, compat encrypts
    expect(await noble.decrypt(compat.encrypt(msg))).toStrictEqual(msg);
  }

  it("tests aes", async () => {
    await testRandom();
    await testRandom(randomBytes(16));
  });
});

describe("test known compat", () => {
  it("tests aes", async () => {
    const key = decodeHex(
      "0000000000000000000000000000000000000000000000000000000000000000"
    );
    const nonce = decodeHex("0xf3e1ba810d2c8900b11312b7c725565f");
    const tag = decodeHex("0Xec3b71e17c11dbe31484da9450edcf6c");
    const encrypted = decodeHex("02d2ffed93b856f148b9");
    const known = concatBytes(encrypted, tag);
    const msg = encoder.encode("helloworld");
    const aad = Uint8Array.from([]);

    const noble = aes(key, nonce, aad);
    const compat = aes256gcm(key, nonce, aad);
    expect(compat.decrypt(known)).toStrictEqual(msg);
    expect(await noble.decrypt(known)).toStrictEqual(msg);
  });
});
