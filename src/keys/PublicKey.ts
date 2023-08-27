import { bytesToHex, equalBytes } from "@noble/ciphers/utils";

import { isHkdfKeyCompressed } from "../config";
import { ETH_PUBLIC_KEY_SIZE, ONE } from "../consts";
import { decodeHex, getSharedKey, getSharedPoint } from "../utils";
import PrivateKey from "./PrivateKey";

export default class PublicKey {
  public static fromHex(hex: string): PublicKey {
    const decoded = decodeHex(hex);
    if (decoded.length === ETH_PUBLIC_KEY_SIZE) {
      // eth public key
      const fixed = new Uint8Array(1 + decoded.length);
      fixed.set([0x04]);
      fixed.set(decoded, 1);
      return new PublicKey(fixed);
    }
    return new PublicKey(decoded);
  }

  public readonly uncompressed: Buffer; // TODO: Uint8Array
  public readonly compressed: Buffer;

  constructor(buffer: Uint8Array) {
    this.uncompressed = Buffer.from(getSharedPoint(ONE, buffer, false));
    this.compressed = Buffer.from(getSharedPoint(ONE, buffer, true));
  }

  public toHex(compressed: boolean = true): string {
    if (compressed) {
      return bytesToHex(this.compressed);
    } else {
      return bytesToHex(this.uncompressed);
    }
  }

  public decapsulate(sk: PrivateKey): Uint8Array {
    let senderPoint: Uint8Array;
    let sharedPoint: Uint8Array;
    if (isHkdfKeyCompressed()) {
      senderPoint = this.compressed;
      sharedPoint = sk.multiply(this, true);
    } else {
      senderPoint = this.uncompressed;
      sharedPoint = sk.multiply(this, false);
    }
    return getSharedKey(senderPoint, sharedPoint);
  }

  public equals(other: PublicKey): boolean {
    return equalBytes(this.uncompressed, other.uncompressed);
  }
}
