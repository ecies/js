"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
exports.__esModule = true;
var secp256k1_1 = __importDefault(require("secp256k1"));
var chai_1 = require("chai");
var keys_1 = require("../keys");
var utils_1 = require("../utils");
describe("test keys", function () {
    it("tests equal", function () {
        var prv = new keys_1.PrivateKey();
        var pub = keys_1.PublicKey.fromHex(prv.publicKey.toHex());
        var isPubEqual = pub.uncompressed.equals(prv.publicKey.uncompressed);
        chai_1.expect(isPubEqual).to.be.equal(true);
        var isFromHexWorking = prv.equals(keys_1.PrivateKey.fromHex(prv.toHex()));
        chai_1.expect(isFromHexWorking).to.be.equal(true);
        var ethPrvHex = "0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d";
        var ethPubHex = "0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140"
            + "a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b";
        var ethPrv = keys_1.PrivateKey.fromHex(ethPrvHex);
        var ethPub = keys_1.PublicKey.fromHex(ethPubHex);
        chai_1.expect(ethPub.equals(ethPrv.publicKey)).to.be.equal(true);
    });
    it("tests ecdh", function () {
        var one = Buffer.from(new Uint8Array(32));
        one[31] = 1;
        var two = Buffer.from(new Uint8Array(32));
        two[31] = 2;
        var k1 = new keys_1.PrivateKey(one);
        var k2 = new keys_1.PrivateKey(two);
        console.log(k1.ecdh(k2.publicKey));
        console.log(one.slice(0, 25));
        chai_1.expect(k1.ecdh(k2.publicKey).equals(k2.ecdh(k1.publicKey))).to.be.equal(true);
    });
});
describe("test string <-> buffer utils ", function () {
    it("tests sha256", function () {
        var digest = utils_1.sha256(Buffer.from(new Uint8Array(16))).toString("hex");
        var allZeroDigest = "374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb";
        chai_1.expect(digest).to.equal(allZeroDigest);
    });
    it("should remove 0x", function () {
        chai_1.expect(utils_1.remove0x("0x0011")).to.equal("0011");
        chai_1.expect(utils_1.remove0x("0011")).to.equal("0011");
        chai_1.expect(utils_1.remove0x("0X0022")).to.equal("0022");
        chai_1.expect(utils_1.remove0x("0022")).to.equal("0022");
    });
    it("should generate valid secret", function () {
        var key = utils_1.getValidSecret();
        chai_1.expect(secp256k1_1["default"].privateKeyVerify(key)).to.equal(true);
    });
    it("should convert hex to buffer", function () {
        var decoded = utils_1.decodeHex("0x0011");
        chai_1.expect(decoded.equals(Buffer.from([0, 0x11]))).to.equal(true);
    });
});
//# sourceMappingURL=crypt.test.js.map