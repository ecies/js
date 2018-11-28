import secp256k1 from "secp256k1";

import { expect } from "chai";
import { randomBytes } from "crypto";
import { decrypt, encrypt } from "../index";
import { PrivateKey, PublicKey } from "../keys";
import { aesDecrypt, aesEncrypt, decodeHex, getValidSecret, remove0x, sha256 } from "../utils";

describe("test aes", () => {
    const text = "helloworld";

    it("tests aes with random key", () => {
        const key = randomBytes(32);
        const data = Buffer.from("this is a test");
        expect(data.equals(aesDecrypt(key, aesEncrypt(key, data)))).to.be.equal(true);
    });

    it("tests aes decrypt with known key and text 'helloworld'", () => {

        const key = Buffer.from(
            decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
        );
        const nonce = Buffer.from(
            decodeHex("f3e1ba810d2c8900b11312b7c725565f"),
        );
        const tag = Buffer.from(
            decodeHex("ec3b71e17c11dbe31484da9450edcf6c"),
        );
        const encrypted = Buffer.from(
            decodeHex("02d2ffed93b856f148b9"),
        );

        const data = Buffer.concat([nonce, tag, encrypted]);
        const decrypted = aesDecrypt(key, data);
        expect(decrypted.toString()).to.be.equal(text);
    });

    it("test aes with key", () => {
        const prv = new PrivateKey(
            decodeHex("0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d"),
        );
        const encrypted = Buffer.from(
            decodeHex(
                "04496071a70de6a27b690d3ccfed47fddd47b5a2e6de389dd661edc4e53a3a67f" +
                "73278cf1e4a74e1a5332b4a6606585385b3d8e05c08a7ced1e3287e8fdc243520" +
                "ff276a665c5fcf9e5767a3ff4e423eec935148c81d4f650191423f1be996cef5e" +
                "deb2fc40387e6b511dd",
            ),
        );

        const decrypted = decrypt(prv.toHex(), encrypted);
        expect(decrypted.toString()).to.be.equal(text);
    });
});

describe("test keys", () => {

    it("tests equal", () => {
        const prv = new PrivateKey();
        const pub = PublicKey.fromHex(prv.publicKey.toHex(false));

        const isPubEqual = pub.uncompressed.equals(prv.publicKey.uncompressed);
        expect(isPubEqual).to.be.equal(true);

        const isFromHexWorking = prv.equals(PrivateKey.fromHex(prv.toHex()));
        expect(isFromHexWorking).to.be.equal(true);

        const ethPrvHex = "0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d";
        const ethPubHex = "0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140"
            + "a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b";

        const ethPrv = PrivateKey.fromHex(ethPrvHex);
        const ethPub = PublicKey.fromHex(ethPubHex);
        expect(ethPub.equals(ethPrv.publicKey)).to.be.equal(true);

    });

    it("tests ecdh", () => {
        const one = Buffer.from(new Uint8Array(32));
        one[31] = 1;
        const two = Buffer.from(new Uint8Array(32));
        two[31] = 2;

        const k1 = new PrivateKey(one);
        const k2 = new PrivateKey(two);
        expect(k1.ecdh(k2.publicKey).equals(k2.ecdh(k1.publicKey))).to.be.equal(true);
    });

});

describe("test string <-> buffer utils ", () => {
    it("tests sha256", () => {
        const digest = sha256(Buffer.from(new Uint8Array(16))).toString("hex");
        const allZeroDigest = "374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb";
        expect(digest).to.equal(allZeroDigest);
    });

    it("should remove 0x", () => {
        expect(remove0x("0x0011")).to.equal("0011");
        expect(remove0x("0011")).to.equal("0011");
        expect(remove0x("0X0022")).to.equal("0022");
        expect(remove0x("0022")).to.equal("0022");
    });

    it("should generate valid secret", () => {
        const key = getValidSecret();
        expect(secp256k1.privateKeyVerify(key)).to.equal(true);
    });

    it("should convert hex to buffer", () => {
        const decoded = decodeHex("0x0011");
        expect(decoded.equals(Buffer.from([0, 0x11]))).to.equal(true);
    });
});
