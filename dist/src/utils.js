"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
exports.__esModule = true;
var secp256k1_1 = __importDefault(require("secp256k1"));
var crypto_1 = require("crypto");
function remove0x(hex) {
    if (hex.startsWith('0x') || hex.startsWith('0X')) {
        return hex.slice(2);
    }
    return hex;
}
exports.remove0x = remove0x;
function getValidSecret() {
    var key;
    do {
        key = crypto_1.randomBytes(32);
    } while (!secp256k1_1["default"].privateKeyVerify(key));
    return key;
}
exports.getValidSecret = getValidSecret;
function decodeHex(hex) {
    return Buffer.from(remove0x(hex), 'hex');
}
exports.decodeHex = decodeHex;
function hello(word) {
    console.log(secp256k1_1["default"].privateKeyVerify(getValidSecret()));
    return "Hello " + word + "!";
}
exports.hello = hello;
//# sourceMappingURL=utils.js.map