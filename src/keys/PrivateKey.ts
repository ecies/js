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
import { PublicKey } from "./PublicKey";

export class PrivateKey {
  public static fromHex(hex: string): PrivateKey {
    return new PrivateKey(decodeHex(hex));
  }

  private readonly data: Uint8Array;
  public readonly publicKey: PublicKey;

  get secret(): Buffer {
    // TODO: Uint8Array
    return Buffer.from(this.data);
  }

  constructor(secret?: Uint8Array) {
    const sk = secret === undefined ? getValidSecret() : secret;
    if (!isValidPrivateKey(sk)) {
      throw new Error("Invalid private key");
    }
    this.data = sk;
    this.publicKey = new PublicKey(getPublicKey(sk));
  }

  public toHex(): string {
    return bytesToHex(this.data);
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
    return getSharedPoint(this.data, pk.compressed, compressed);
  }

  public equals(other: PrivateKey): boolean {
    return equalBytes(this.data, other.data);
  }
}
