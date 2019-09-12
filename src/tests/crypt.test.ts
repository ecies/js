import axios from "axios";
import { expect } from "chai";
import { randomBytes } from "crypto";
import { stringify } from "querystring";

import { decrypt, encrypt } from "../index";
import { PrivateKey } from "../keys";
import { aesDecrypt, aesEncrypt, decodeHex } from "../utils";

const PYTHON_BACKEND = "https://eciespy.herokuapp.com/";

describe("test encrypt and decrypt", () => {
    const TEXT = "helloworld";

    it("tests aes with random key", () => {
        const key = randomBytes(32);
        const data = Buffer.from("this is a test");
        expect(data.equals(aesDecrypt(key, aesEncrypt(key, data)))).to.be.equal(true);
    });

    it("tests aes decrypt with known key and TEXT", () => {
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
        expect(decrypted.toString()).to.be.equal(TEXT);
    });

    it("tests encrypt/decrypt buffer", () => {
        const prv1 = new PrivateKey();
        const encrypted1 = encrypt(prv1.publicKey.uncompressed, Buffer.from(TEXT));
        expect(decrypt(prv1.secret, encrypted1).toString()).to.be.equal(TEXT);

        const prv2 = new PrivateKey();
        const encrypted2 = encrypt(prv2.publicKey.compressed, Buffer.from(TEXT));
        expect(decrypt(prv2.secret, encrypted2).toString()).to.be.equal(TEXT);
    });

    it("tests encrypt/decrypt hex", () => {
        const prv1 = new PrivateKey();
        const encrypted1 = encrypt(prv1.publicKey.toHex(), Buffer.from(TEXT));
        expect(decrypt(prv1.toHex(), encrypted1).toString()).to.be.equal(TEXT);

        const prv2 = new PrivateKey();
        const encrypted2 = encrypt(prv2.publicKey.toHex(), Buffer.from(TEXT));
        expect(decrypt(prv2.toHex(), encrypted2).toString()).to.be.equal(TEXT);
    });

    it("tests encrypt/decrypt against python version", () => {
        const prv = new PrivateKey();

        axios.post(PYTHON_BACKEND, stringify({
            data: TEXT,
            pub: prv.publicKey.toHex(),
        })).then((res) => {
            const encryptedKnown = Buffer.from(decodeHex(res.data));
            const decrypted = decrypt(prv.toHex(), encryptedKnown);
            expect(decrypted.toString()).to.be.equal(TEXT);
        });

        const encrypted = encrypt(prv.publicKey.toHex(), Buffer.from(TEXT));
        axios.post(PYTHON_BACKEND, stringify({
            data: encrypted.toString("hex"),
            prv: prv.toHex(),
        })).then((res) => {
            expect(TEXT).to.be.equal(res.data);
        });
    });
});
