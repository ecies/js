import { bytesToHex, equalBytes } from "@noble/ciphers/utils";

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

  /** @description From version 0.5.0, `Uint8Array` will be returned instead of `Buffer`. */
  get secret(): Buffer {
    // TODO: Uint8Array
    return Buffer.from(this.data);
  }

  constructor(secret?: Uint8Array) {
    if (secret === undefined) {
      this.data = getValidSecret();
    } else if (isValidPrivateKey(secret)) {
      this.data = secret;
    } else {
      throw new Error("Invalid private key");
    }
    this.publicKey = new PublicKey(getPublicKey(this.data));
  }

  public toHex(): string {
    return bytesToHex(this.data);
  }

  /**
   * Derives a shared secret from ephemeral private key (this) and receiver's public key (pk).
   * @description The shared key is 32 bytes, derived with `HKDF-SHA256(senderPoint || sharedPoint)`. See implementation for details.
   *
   * There are some variations in different ECIES implementations:
   * which key derivation function to use, compressed or uncompressed `senderPoint`/`sharedPoint`, whether to include `senderPoint`, etc.
   *
   * Because the entropy of `senderPoint`, `sharedPoint` is enough high[1], we don't need salt to derive keys.
   *
   * [1]: Two reasons: the public keys are "random" bytes (albeit secp256k1 public keys are **not uniformly** random), and ephemeral keys are generated in every encryption.
   *
   * @param pk - Receiver's public key.
   * @param compressed - (default: `false`) Whether to use compressed or uncompressed public keys in the key derivation (secp256k1 only).
   * @returns Shared secret, derived with HKDF-SHA256.
   */
  public encapsulate(pk: PublicKey, compressed: boolean = false): Uint8Array {
    const senderPoint = this.publicKey.toBytes(compressed);
    const sharedPoint = this.multiply(pk, compressed);
    return getSharedKey(senderPoint, sharedPoint);
  }

  public multiply(pk: PublicKey, compressed: boolean = false): Uint8Array {
    return getSharedPoint(this.data, pk.toBytes(true), compressed);
  }

  public equals(other: PrivateKey): boolean {
    return equalBytes(this.data, other.data);
  }
}
