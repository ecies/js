import { secp256k1 } from "@noble/curves/secp256k1";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

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
    if (!secp256k1.utils.isValidPrivateKey(this.secret)) {
      throw new Error("Invalid private key");
    }
    this.publicKey = new PublicKey(Buffer.from(secp256k1.getPublicKey(this.secret)));
  }

  public toHex(): string {
    return this.secret.toString("hex");
  }

  public encapsulate(pub: PublicKey): Buffer {
    const master = Buffer.concat([this.publicKey.uncompressed, this.multiply(pub)]);
    return Buffer.from(hkdf(sha256, master, undefined, undefined, 32));
  }

  public multiply(pub: PublicKey): Buffer {
    return Buffer.from(secp256k1.getSharedSecret(this.secret, pub.compressed, false));
  }

  public equals(other: PrivateKey): boolean {
    return this.secret.equals(other.secret);
  }
}
