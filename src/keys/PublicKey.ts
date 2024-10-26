import { bytesToHex, equalBytes } from "@noble/ciphers/utils";

import { convertPublicKeyFormat, getSharedKey, hexToPublicKey } from "../utils";
import type { PrivateKey } from "./PrivateKey";

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

  /**
   * Derives a shared secret from receiver's private key (sk) and ephemeral public key (this).
   * Opposite of `encapsulate`.
   * @see PrivateKey.encapsulate
   *
   * @param sk - Receiver's private key.
   * @param compressed - Whether to use compressed or uncompressed public keys in the key derivation (secp256k1 only).
   * @returns Shared secret, derived with HKDF-SHA256.
   */
  public decapsulate(sk: PrivateKey, compressed: boolean = false): Uint8Array {
    const senderPoint = compressed ? this.data : this.uncompressed;
    const sharedPoint = sk.multiply(this, compressed);
    return getSharedKey(senderPoint, sharedPoint);
  }

  public equals(other: PublicKey): boolean {
    return equalBytes(this.data, other.data);
  }
}
