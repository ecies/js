import { PrivateKey, PublicKey } from "./keys";
import { aesDecrypt, aesEncrypt, decodeHex, getValidSecret, remove0x } from "./utils";
import { UNCOMPRESSED_PUBLIC_KEY_SIZE } from "./consts";

export function encrypt(receiverRawPub: string | Buffer, msg: Buffer): Buffer {
    const ephemeralKey = new PrivateKey();

    const receiverPubkey =
        receiverRawPub instanceof Buffer
            ? new PublicKey(receiverRawPub)
            : PublicKey.fromHex(receiverRawPub);

    const aesKey = ephemeralKey.encapsulate(receiverPubkey);
    const encrypted = aesEncrypt(aesKey, msg);
    return Buffer.concat([ephemeralKey.publicKey.uncompressed, encrypted]);
}

export function decrypt(receiverRawPrv: string | Buffer, msg: Buffer): Buffer {
    const receiverPrvkey =
        receiverRawPrv instanceof Buffer
            ? new PrivateKey(receiverRawPrv)
            : PrivateKey.fromHex(receiverRawPrv);

    const senderPubkey = new PublicKey(msg.slice(0, UNCOMPRESSED_PUBLIC_KEY_SIZE));
    const encrypted = msg.slice(UNCOMPRESSED_PUBLIC_KEY_SIZE);
    const aesKey = senderPubkey.decapsulate(receiverPrvkey);
    return aesDecrypt(aesKey, encrypted);
}

export { PrivateKey, PublicKey } from "./keys";

export const utils = {
    aesDecrypt,
    aesEncrypt,
    decodeHex,
    getValidSecret,
    remove0x,
};
