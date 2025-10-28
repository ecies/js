import { bytesToHex, equalBytes } from "@noble/ciphers/utils";

import type { EllipticCurve } from "../config.js";
import { convertPublicKeyFormat, getSharedKey, hexToPublicKey } from "../utils/index.js";
import type { PrivateKey } from "./PrivateKey.js";

export class PublicKey {
  public static fromHex(hex: string, curve?: EllipticCurve): PublicKey {
    return new PublicKey(hexToPublicKey(hex, curve), curve);
  }

  private readonly data: Uint8Array; // always compressed if secp256k1
  private readonly dataUncompressed: Uint8Array | null;

  private get _uncompressed(): Uint8Array {
    return this.dataUncompressed !== null ? this.dataUncompressed : this.data;
  }

  /** @deprecated - use `PublicKey.toBytes(false)` instead. You may also need `Buffer.from`. */
  get uncompressed(): Buffer {
    return Buffer.from(this._uncompressed); // TODO: delete
  }

  /** @deprecated - use `PublicKey.toBytes()` instead. You may also need `Buffer.from`. */
  get compressed(): Buffer {
    return Buffer.from(this.data); // TODO: delete
  }

  constructor(data: Uint8Array, curve?: EllipticCurve) {
    // data can be either compressed or uncompressed if secp256k1
    const compressed = convertPublicKeyFormat(data, true, curve);
    const uncompressed = convertPublicKeyFormat(data, false, curve);
    this.data = compressed;
    this.dataUncompressed =
      compressed.length !== uncompressed.length ? uncompressed : null;
  }

  public toBytes(compressed: boolean = true): Uint8Array {
    return compressed ? this.data : this._uncompressed;
  }

  public toHex(compressed: boolean = true): string {
    return bytesToHex(this.toBytes(compressed));
  }

  /**
   * Derives a shared secret from receiver's private key (sk) and ephemeral public key (this).
   * Opposite of `encapsulate`.
   * @see PrivateKey.encapsulate
   *
   * @param sk - Receiver's private key.
   * @param compressed - (default: `false`) Whether to use compressed or uncompressed public keys in the key derivation (secp256k1 only).
   * @returns Shared secret, derived with HKDF-SHA256.
   */
  public decapsulate(sk: PrivateKey, compressed: boolean = false): Uint8Array {
    const senderPoint = this.toBytes(compressed);
    const sharedPoint = sk.multiply(this, compressed);
    return getSharedKey(senderPoint, sharedPoint);
  }

  public equals(other: PublicKey): boolean {
    return equalBytes(this.data, other.data);
  }
}
