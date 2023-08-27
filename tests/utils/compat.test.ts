import { concatBytes } from "@noble/ciphers/utils";
import { aes_256_gcm as aes } from "@noble/ciphers/webcrypto/aes";
import { randomBytes } from "@noble/ciphers/webcrypto/utils";

import { decodeHex } from "../../src/utils";
import { aes256gcm } from "../../src/utils/compat";

const TEXT = "helloworld🌍";
const encoder = new TextEncoder();

describe("test compat utils", () => {
  const msg = encoder.encode(TEXT);

  async function testRandom() {
    const key = randomBytes();
    const nonce = randomBytes(16);
    // @ts-ignore
    const noble = aes(key, nonce);
    const compat = aes256gcm(key, nonce);
    // same encryption
    expect(await noble.encrypt(msg)).toStrictEqual(compat.encrypt(msg));
    // noble encrypts compat decrypts
    expect(compat.decrypt(await noble.encrypt(msg))).toStrictEqual(msg);
    // noble decrypts compat encrypts
    expect(await noble.decrypt(compat.encrypt(msg))).toStrictEqual(msg);
  }

  it("test aes random", async () => {
    await testRandom();
  });

  it("test aes known key", async () => {
    const key = decodeHex(
      "0000000000000000000000000000000000000000000000000000000000000000"
    );
    const nonce = decodeHex("0xf3e1ba810d2c8900b11312b7c725565f");
    const tag = decodeHex("0Xec3b71e17c11dbe31484da9450edcf6c");
    const encrypted = decodeHex("02d2ffed93b856f148b9");
    const known = concatBytes(encrypted, tag);
    const msg = encoder.encode("helloworld");

    const noble = aes(key, nonce);
    const compat = aes256gcm(key, nonce, Uint8Array.from([]));
    expect(compat.decrypt(known)).toStrictEqual(msg);
    expect(await noble.decrypt(known)).toStrictEqual(compat.decrypt(known));
  });
});
