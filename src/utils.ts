import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import secp256k1 from "secp256k1";

export function remove0x(hex: string): string {
    if (hex.startsWith("0x") || hex.startsWith("0X")) {
        return hex.slice(2);
    }
    return hex;
}

export function decodeHex(hex: string): Buffer {
    return Buffer.from(remove0x(hex), "hex");
}

export function getValidSecret(): Buffer {
    let key: Buffer;
    do {
        key = randomBytes(32);
    } while (!secp256k1.privateKeyVerify(key));
    return key;
}

export function aesEncrypt(key: Buffer, plainText: Buffer): Buffer {
    const nonce = randomBytes(16);
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([nonce, tag, encrypted]);
}

export function aesDecrypt(key: Buffer, cipherText: Buffer): Buffer {
    const nonce = cipherText.slice(0, 16);
    const tag = cipherText.slice(16, 32);
    const ciphered = cipherText.slice(32);
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphered), decipher.final()]);
}
