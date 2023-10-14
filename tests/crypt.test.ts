import { randomBytes } from "crypto";

import { decrypt, encrypt } from "../src/index";
import { PrivateKey, PublicKey } from "../src/keys";
import { aesDecrypt, aesEncrypt, decodeHex } from "../src/utils";

describe("test encrypt and decrypt", () => {
  const TEXT = "helloworld";

  it("tests aes with random key", () => {
    const key = randomBytes(32);
    const data = Buffer.from("this is a test");
    expect(data.equals(aesDecrypt(key, aesEncrypt(key, data)))).toEqual(true);
  });

  it("tests aes decrypt with known key and TEXT", () => {
    const key = Buffer.from(
      decodeHex("0000000000000000000000000000000000000000000000000000000000000000")
    );
    const nonce = Buffer.from(decodeHex("f3e1ba810d2c8900b11312b7c725565f"));
    const tag = Buffer.from(decodeHex("ec3b71e17c11dbe31484da9450edcf6c"));
    const encrypted = Buffer.from(decodeHex("02d2ffed93b856f148b9"));

    const data = Buffer.concat([nonce, tag, encrypted]);
    const decrypted = aesDecrypt(key, data);
    expect(decrypted.toString()).toEqual(TEXT);
  });

  it("tests encrypt/decrypt buffer", () => {
    const prv1 = new PrivateKey();
    const encrypted1 = encrypt(prv1.publicKey.uncompressed, Buffer.from(TEXT));
    expect(decrypt(prv1.secret, encrypted1).toString()).toEqual(TEXT);

    const prv2 = new PrivateKey();
    const encrypted2 = encrypt(prv2.publicKey.compressed, Buffer.from(TEXT));
    expect(decrypt(prv2.secret, encrypted2).toString()).toEqual(TEXT);
  });

  it("tests encrypt/decrypt hex", () => {
    const prv1 = new PrivateKey();
    const encrypted1 = encrypt(prv1.publicKey.toHex(), Buffer.from(TEXT));
    expect(decrypt(prv1.toHex(), encrypted1).toString()).toEqual(TEXT);

    const prv2 = new PrivateKey();
    const encrypted2 = encrypt(prv2.publicKey.toHex(), Buffer.from(TEXT));
    expect(decrypt(prv2.toHex(), encrypted2).toString()).toEqual(TEXT);
  });

  it("tests sk pk", () => {
    const sk = PrivateKey.fromHex(
      "5b5b1a0ff51e4350badd6f58d9e6fa6f57fbdbde6079d12901770dda3b803081"
    );
    const pk = PublicKey.fromHex(
      "048e41409f2e109f2d704f0afd15d1ab53935fd443729913a7e8536b4cef8cf5773d4db7bbd99e9ed64595e24a251c9836f35d4c9842132443c17f6d501b3410d2"
    );
    const enc = encrypt(pk.toHex(), Buffer.from(TEXT));
    expect(decrypt(sk.toHex(), enc).toString()).toEqual(TEXT);
  });
});
