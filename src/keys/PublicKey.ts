import { bytesToHex, equalBytes } from "@noble/ciphers/utils";

import { ECIES_CONFIG, type EllipticCurve } from "../config.js";

import { convertPublicKeyFormat, getSharedKey, hexToPublicKey } from "../utils/index.js";
import type { PrivateKey } from "./PrivateKey.js";

export class PublicKey {
  /**
   * Creates a `PublicKey` instance from a hexadecimal string.
   * @param hex - The hexadecimal string representing the public key.
   * @param curve - (optional) The elliptic curve to use (default: `ECIES_CONFIG.ellipticCurve`).
   * @returns A new `PublicKey` instance.
   */
  public static fromHex(
    hex: string,
    curve: EllipticCurve = ECIES_CONFIG.ellipticCurve
  ): PublicKey {
    return new PublicKey(hexToPublicKey(curve, hex), curve);
  }

  private readonly data: Uint8Array; // always compressed if secp256k1
  private readonly dataUncompressed: Uint8Array | null;

  private get _uncompressed(): Uint8Array {
    return this.dataUncompressed !== null ? this.dataUncompressed : this.data;
  }

  /**
   * Constructs a `PublicKey` instance from a byte array.
   * @param data - The byte array representing the public key (compressed or uncompressed if secp256k1).
   * @param curve - (optional) The elliptic curve to use (default: `ECIES_CONFIG.ellipticCurve`).
   */
  constructor(data: Uint8Array, curve: EllipticCurve = ECIES_CONFIG.ellipticCurve) {
    // data can be either compressed or uncompressed if secp256k1
    const compressed = convertPublicKeyFormat(curve, data, true);
    const uncompressed = convertPublicKeyFormat(curve, data, false);
    this.data = compressed;
    this.dataUncompressed = compressed.length !== uncompressed.length ? uncompressed : null;
  }

  /**
   * Converts the public key to bytes in compressed or uncompressed format.
   * @param compressed - (default: `true`) Whether to return the public key in compressed or uncompressed format (secp256k1 only).
   * @returns The public key as a Uint8Array.
   */
  public toBytes(compressed: boolean = true): Uint8Array {
    return compressed ? this.data : this._uncompressed;
  }

  /**
   * Converts the public key to a hexadecimal string in compressed or uncompressed format.
   * @param compressed - (default: `true`) Whether to return the public key in compressed or uncompressed format (secp256k1 only).
   * @returns The public key as a hexadecimal string.
   */
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

  /**
   * Compares this public key with another for equality.
   * @param other - The other `PublicKey` to compare with.
   * @returns `true` if the public keys are equal, `false` otherwise.
   */
  public equals(other: PublicKey): boolean {
    return equalBytes(this.data, other.data);
  }
}
