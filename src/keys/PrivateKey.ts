import { bytesToHex, equalBytes } from "@noble/ciphers/utils";

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

  public readonly secret: Buffer; // TODO: Uint8Array
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
    return bytesToHex(this.secret);
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

  public multiply(pk: PublicKey, compressed: boolean = false): Uint8Array {
    return getSharedPoint(this.secret, pk.compressed, compressed);
  }

  public equals(other: PrivateKey): boolean {
    return equalBytes(this.secret, other.secret);
  }
}
