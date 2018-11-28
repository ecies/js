"use strict";
exports.__esModule = true;
var chai_1 = require("chai");
var utils_1 = require("../src/utils");
describe('test string <-> buffer utils ', function () {
    it('should remove 0x', function () {
        chai_1.expect(utils_1.remove0x('0x0011')).to.equal('0011');
        chai_1.expect(utils_1.remove0x('0X0022')).to.equal('0022');
    });
    it('should convert hex to buffer', function () {
        var decoded = utils_1.decodeHex('0x0011');
        chai_1.expect(decoded.equals(Buffer.from([0, 0x11]))).to.be["true"];
    });
});
//# sourceMappingURL=crypt.test.js.map