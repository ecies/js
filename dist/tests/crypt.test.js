"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
exports.__esModule = true;
var secp256k1_1 = __importDefault(require("secp256k1"));
var chai_1 = require("chai");
var utils_1 = require("../utils");
describe("test string <-> buffer utils ", function () {
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