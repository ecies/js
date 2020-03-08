import hkdf from "futoin-hkdf";
import secp256k1 from "secp256k1";

import { decodeHex, getValidSecret } from "../utils";
import PublicKey from "./PublicKey";

export default class PrivateKey {

    public static fromHex(hex: string): PrivateKey {
        return new PrivateKey(decodeHex(hex));
    }

    public readonly secret: Buffer;
    public readonly publicKey: PublicKey;

    constructor(secret?: Buffer) {
        this.secret = secret || getValidSecret();
        if (!secp256k1.privateKeyVerify(this.secret)) {
            throw new Error("Invalid private key");
        }
        this.publicKey = new PublicKey(Buffer.from(secp256k1.publicKeyCreate(this.secret)));
    }

    public toHex(): string {
        return `0x${this.secret.toString("hex")}`;
    }

    public encapsulate(pub: PublicKey): Buffer {
        const master = Buffer.concat([
            this.publicKey.uncompressed,
            this.multiply(pub),
        ]);
        return hkdf(master, 32, {
            hash: "SHA-256",
        });
    }

    public multiply(pub: PublicKey): Buffer {
        return Buffer.from(secp256k1.publicKeyTweakMul(pub.compressed, this.secret, false));
    }

    public equals(other: PrivateKey): boolean {
        return this.secret.equals(other.secret);
    }
}
