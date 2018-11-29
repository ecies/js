import secp256k1 from "secp256k1";

import { expect } from "chai";
import { decodeHex, getValidSecret, remove0x, sha256 } from "../utils";

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
