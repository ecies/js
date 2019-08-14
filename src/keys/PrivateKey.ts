import hkdf from "futoin-hkdf";
import secp256k1 from "secp256k1";

import {decodeHex, getValidSecret} from "../utils";
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
        this.publicKey = new PublicKey(secp256k1.publicKeyCreate(this.secret));
    }

    public toHex(): string {
        return `0x${this.secret.toString("hex")}`;
    }

    public encapsulateKEM(pub: PublicKey) {
        return hkdf(Buffer.concat([
            this.publicKey.uncompressed,
            secp256k1.ecdhUnsafe(pub.compressed, this.secret),
        ]), 32, {
            hash: "SHA-256",
        });
    }

    public ecdh(pub: PublicKey) {
        return secp256k1.ecdh(pub.compressed, this.secret);
    }

    public equals(other: PrivateKey): boolean {
        return this.secret.equals(other.secret);
    }
}
