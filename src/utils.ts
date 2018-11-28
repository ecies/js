import { randomBytes } from "crypto";
import secp256k1 from "secp256k1";

export function remove0x(hex: string): string {
    if (hex.startsWith("0x") || hex.startsWith("0X")) {
        return hex.slice(2);
    }
    return hex;
}

export function getValidSecret(): Buffer {
    let key: Buffer;
    do {
        key = randomBytes(32);
    } while (!secp256k1.privateKeyVerify(key));
    return key;
}

export function decodeHex(hex: string): Buffer {
    return Buffer.from(remove0x(hex), "hex");
}

export function hello(word: string): string {
    console.log(secp256k1.privateKeyVerify(getValidSecret()));
    return `Hello ${word}!`;
}
