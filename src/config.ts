import {
  COMPRESSED_PUBLIC_KEY_SIZE,
  CURVE25519_PUBLIC_KEY_SIZE,
  UNCOMPRESSED_PUBLIC_KEY_SIZE,
} from "./consts.js";

export type EllipticCurve = "secp256k1" | "x25519" | "ed25519";
export type SymmetricAlgorithm = "aes-256-gcm" | "xchacha20";
export type NonceLength = 12 | 16; // aes-256-gcm only

export class Config {
  ellipticCurve: EllipticCurve = "secp256k1";
  isEphemeralKeyCompressed: boolean = false; // secp256k1 only
  isHkdfKeyCompressed: boolean = false; // secp256k1 only
  symmetricAlgorithm: SymmetricAlgorithm = "aes-256-gcm";
  symmetricNonceLength: NonceLength = 16; // aes-256-gcm only

  get ephemeralKeySize(): number {
    const mapping = {
      secp256k1: this.isEphemeralKeyCompressed
        ? COMPRESSED_PUBLIC_KEY_SIZE
        : UNCOMPRESSED_PUBLIC_KEY_SIZE,
      x25519: CURVE25519_PUBLIC_KEY_SIZE,
      ed25519: CURVE25519_PUBLIC_KEY_SIZE,
    };

    /* v8 ignore else -- @preserve */
    if (this.ellipticCurve in mapping) {
      return mapping[this.ellipticCurve];
    } else {
      throw new Error("Not implemented");
    }
  }
}

export const ECIES_CONFIG = new Config();
