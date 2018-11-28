import secp256k1 from "secp256k1";

import { triggerAsyncId } from "async_hooks";
import { expect } from "chai";
import { PrivateKey, PublicKey } from "../keys";
import { decodeHex, getValidSecret, remove0x, sha256 } from "../utils";

describe("test keys", () => {

    it("tests equal", () => {
        const prv = new PrivateKey();
        const pub = PublicKey.fromHex(prv.publicKey.toHex());

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
        console.log(k1.ecdh(k2.publicKey));
        console.log(one.slice(0, 25));
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
