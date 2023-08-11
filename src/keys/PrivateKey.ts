import { isHkdfKeyCompressed } from "../config";
import {
  decodeHex,
  getPublicKey,
  getSharedKey,
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

  constructor(secret?: Uint8Array) {
    const sk = secret === undefined ? getValidSecret() : secret;
    if (!isValidPrivateKey(sk)) {
      throw new Error("Invalid private key");
    }
    this.secret = Buffer.from(sk);
    this.publicKey = new PublicKey(getPublicKey(sk));
  }

  public toHex(): string {
    return this.secret.toString("hex");
  }

  public encapsulate(pk: PublicKey): Uint8Array {
    let senderPoint: Uint8Array;
    let sharedPoint: Uint8Array;
    if (isHkdfKeyCompressed()) {
      senderPoint = this.publicKey.compressed;
      sharedPoint = this.multiply(pk, true);
    } else {
      senderPoint = this.publicKey.uncompressed;
      sharedPoint = this.multiply(pk, false);
    }
    return getSharedKey(senderPoint, sharedPoint);
  }

  public multiply(pub: PublicKey, compressed: boolean = false): Uint8Array {
    return getSharedPoint(this.secret, pub.compressed, compressed);
  }

  public equals(other: PrivateKey): boolean {
    return this.secret.equals(other.secret);
  }
}
