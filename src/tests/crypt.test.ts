import axios from "axios";
import { expect } from "chai";
import { randomBytes } from "crypto";
import { stringify } from "querystring";

import { decrypt, encrypt } from "../index";
import { PrivateKey, PublicKey } from "../keys";
import { aesDecrypt, aesEncrypt, decodeHex } from "../utils";

const ETH_PRVHEX = "0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d";
const ETH_PUBHEX = "0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140"
    + "a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b";
const PYTHON_BACKEND = "https://eciespy.herokuapp.com/";

describe("test encrypt and decrypt", () => {
    const text = "helloworld";
    const config = {
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
    };

    it("tests aes with random key", () => {
        const key = randomBytes(32);
        const data = Buffer.from("this is a test");
        expect(data.equals(aesDecrypt(key, aesEncrypt(key, data)))).to.be.equal(true);
    });

    it("tests aes decrypt with known key and text", () => {

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

    it("test encrypt/decrypt against python version", () => {
        const prv = new PrivateKey(
            decodeHex(ETH_PRVHEX),
        );

        axios.post(PYTHON_BACKEND, stringify({
            data: text,
            pub: ETH_PUBHEX,
        })).then((res) => {
            const encryptedKnown = Buffer.from(decodeHex(res.data));
            const decrypted = decrypt(prv.toHex(), encryptedKnown);
            expect(decrypted.toString()).to.be.equal(text);
        });

        const encrypted = encrypt(prv.publicKey.toHex(), Buffer.from(text));
        axios.post(PYTHON_BACKEND, stringify({
            data: encrypted.toString("hex"),
            prv: prv.toHex(),
        })).then((res) => {
            expect(text).to.be.equal(res.data);
        });
    });
});

describe("test keys", () => {

    it("test invalid", () => {
        // 0 < private key < group order int
        const groupOrderInt = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        expect(() => new PrivateKey(decodeHex(groupOrderInt))).to.throw(Error);

        const groupOrderIntAdd1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
        expect(() => new PrivateKey(decodeHex(groupOrderIntAdd1))).to.throw(Error);

        expect(() => new PrivateKey(decodeHex("0"))).to.throw(Error);
    });

    it("tests equal", () => {
        const prv = new PrivateKey();
        const pub = PublicKey.fromHex(prv.publicKey.toHex(false));

        const isPubEqual = pub.uncompressed.equals(prv.publicKey.uncompressed);
        expect(isPubEqual).to.be.equal(true);

        const isFromHexWorking = prv.equals(PrivateKey.fromHex(prv.toHex()));
        expect(isFromHexWorking).to.be.equal(true);

    });

    it("tests eth key compatibility", () => {
        const ethPrv = PrivateKey.fromHex(ETH_PRVHEX);
        const ethPub = PublicKey.fromHex(ETH_PUBHEX);
        expect(ethPub.equals(ethPrv.publicKey)).to.be.equal(true);
    });

    it("tests multiply and hkdf", () => {
        const two = Buffer.from(new Uint8Array(32));
        two[31] = 2;
        const three = Buffer.from(new Uint8Array(32));
        three[31] = 3;

        const k1 = new PrivateKey(two);
        const k2 = new PrivateKey(three);
        expect(k1.multiply(k2.publicKey).equals(k2.multiply(k1.publicKey))).to.be.equal(true);

        const derived = k1.encapsulate(k2.publicKey);
        const anotherDerived = k1.publicKey.decapsulate(k2);
        const knownDerived = Buffer.from(decodeHex(
            "6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82",
        ));
        expect(derived.equals(knownDerived)).to.be.equal(true);
        expect(anotherDerived.equals(knownDerived)).to.be.equal(true);
    });

});
