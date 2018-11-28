import { PrivateKey, PublicKey } from "./keys";
import { } from "./utils";

function encrypt(receiverPubhex: string, msg: Buffer): Buffer {
    const disposableKey = new PrivateKey();
    const receiverPubkey = PublicKey.fromHex(receiverPubhex);
    const aesKey = disposableKey.ecdh(receiverPubkey);
    return Buffer.from([0]);
}

function decrypt(receiverPrvhex: string, msg: Buffer): Buffer {
    const receiverPrvkey = PrivateKey.fromHex(receiverPrvhex);
    const senderPubkey = new PublicKey(msg.slice(0, 65));
    const encrypted = msg.slice(65);
    const aesKey = receiverPrvkey.ecdh(senderPubkey);
    return Buffer.from([0]);
}
