import { bytesToHex, equalBytes } from "@noble/ciphers/utils";

import { isHkdfKeyCompressed } from "../config";
import { convertPublicKeyFormat, getSharedKey, hexToPublicKey } from "../utils";
import { PrivateKey } from "./PrivateKey";

export class PublicKey {
  public static fromHex(hex: string): PublicKey {
    return new PublicKey(hexToPublicKey(hex));
  }

  private readonly data: Uint8Array; // always compressed if secp256k1

  get uncompressed(): Buffer {
    // TODO: Uint8Array
    return Buffer.from(convertPublicKeyFormat(this.data, false));
  }

  get compressed(): Buffer {
    // TODO: Uint8Array
    return Buffer.from(this.data);
  }

  constructor(data: Uint8Array) {
    this.data = convertPublicKeyFormat(data, true);
  }

  public toHex(compressed: boolean = true): string {
    if (compressed) {
      return bytesToHex(this.data);
    } else {
      return bytesToHex(this.uncompressed);
    }
  }

  public decapsulate(sk: PrivateKey): Uint8Array {
    let senderPoint: Uint8Array;
    let sharedPoint: Uint8Array;
    if (isHkdfKeyCompressed()) {
      senderPoint = this.data;
      sharedPoint = sk.multiply(this, true);
    } else {
      senderPoint = this.uncompressed;
      sharedPoint = sk.multiply(this, false);
    }
    return getSharedKey(senderPoint, sharedPoint);
  }

  public equals(other: PublicKey): boolean {
    return equalBytes(this.data, other.data);
  }
}
