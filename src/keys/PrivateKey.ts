import { isHkdfKeyCompressed } from "../config";
import {
  decodeHex,
  deriveKey,
  getPublicKey,
  getSharedPoint,
  getValidSecret,
  isValidPrivateKey,
} from "../utils";
import PublicKey from "./PublicKey";

export default class PrivateKey {
  public static fromHex(hex: string): PrivateKey {
    return new PrivateKey(decodeHex(hex));
  }

  public readonly secret: Buffer;
  public readonly publicKey: PublicKey;

  constructor(secret?: Buffer) {
    this.secret = secret === undefined ? getValidSecret() : secret;
    if (!isValidPrivateKey(this.secret)) {
      throw new Error("Invalid private key");
    }
    this.publicKey = new PublicKey(getPublicKey(this.secret));
  }

  public toHex(): string {
    return this.secret.toString("hex");
  }

  public encapsulate(pub: PublicKey): Buffer {
    let master: Buffer;

    if (isHkdfKeyCompressed()) {
      master = Buffer.concat([this.publicKey.compressed, this.multiply(pub, true)]);
    } else {
      master = Buffer.concat([this.publicKey.uncompressed, this.multiply(pub, false)]);
    }
    return deriveKey(master);
  }

  public multiply(pub: PublicKey, compressed: boolean = false): Buffer {
    return getSharedPoint(this.secret, pub.compressed, compressed);
  }

  public equals(other: PrivateKey): boolean {
    return this.secret.equals(other.secret);
  }
}
