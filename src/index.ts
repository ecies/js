import { PrivateKey, PublicKey } from "./keys";
import { aesDecrypt, aesEncrypt, decodeHex, getValidSecret, remove0x, sha256 } from "./utils";

export function encrypt(receiverPubhex: string, msg: Buffer): Buffer {
    const disposableKey = new PrivateKey();
    const receiverPubkey = PublicKey.fromHex(receiverPubhex);
    const aesKey = disposableKey.ecdh(receiverPubkey);
    const encrypted = aesEncrypt(aesKey, msg);
    return Buffer.concat([disposableKey.publicKey.uncompressed, encrypted]);
}

export function decrypt(receiverPrvhex: string, msg: Buffer): Buffer {
    const receiverPrvkey = PrivateKey.fromHex(receiverPrvhex);
    const senderPubkey = new PublicKey(msg.slice(0, 65));
    const encrypted = msg.slice(65);
    const aesKey = receiverPrvkey.ecdh(senderPubkey);
    return aesDecrypt(aesKey, encrypted);
}

export { PrivateKey, PublicKey } from "./keys";

export const utils = {
    aesDecrypt, aesEncrypt, decodeHex, getValidSecret, remove0x, sha256,
};
