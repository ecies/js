"use strict";
exports.__esModule = true;
var keys_1 = require("./keys");
function encrypt(receiverPubhex, msg) {
    var disposableKey = new keys_1.PrivateKey();
    var receiverPubkey = keys_1.PublicKey.fromHex(receiverPubhex);
    var aesKey = disposableKey.ecdh(receiverPubkey);
    return Buffer.from([0]);
}
function decrypt(receiverPrvhex, msg) {
    var receiverPrvkey = keys_1.PrivateKey.fromHex(receiverPrvhex);
    var senderPubkey = new keys_1.PublicKey(msg.slice(0, 65));
    var encrypted = msg.slice(65);
    var aesKey = receiverPrvkey.ecdh(senderPubkey);
    return Buffer.from([0]);
}
//# sourceMappingURL=index.js.map