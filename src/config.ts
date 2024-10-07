import {
  COMPRESSED_PUBLIC_KEY_SIZE,
  CURVE25519_PUBLIC_KEY_SIZE,
  UNCOMPRESSED_PUBLIC_KEY_SIZE,
} from "./consts";

export type EllipticCurve = "secp256k1" | "x25519" | "ed25519";
export type SymmetricAlgorithm =
  | "aes-256-gcm"
  | "xchacha20"
  | "aes-256-cbc" /* NOT RECOMMENDED, only for compatibility */;
export type NonceLength = 12 | 16; // aes-256-gcm only

class Config {
  ellipticCurve: EllipticCurve = "secp256k1";
  isEphemeralKeyCompressed: boolean = false; // secp256k1 only
  isHkdfKeyCompressed: boolean = false; // secp256k1 only
  symmetricAlgorithm: SymmetricAlgorithm = "aes-256-gcm";
  symmetricNonceLength: NonceLength = 16; // aes-256-gcm only
}

export const ECIES_CONFIG = new Config();

export const ellipticCurve = () => ECIES_CONFIG.ellipticCurve;
export const isEphemeralKeyCompressed = () => ECIES_CONFIG.isEphemeralKeyCompressed;
export const isHkdfKeyCompressed = () => ECIES_CONFIG.isHkdfKeyCompressed;
export const symmetricAlgorithm = () => ECIES_CONFIG.symmetricAlgorithm;
export const symmetricNonceLength = () => ECIES_CONFIG.symmetricNonceLength;

export const ephemeralKeySize = () => {
  const mapping = {
    secp256k1: ECIES_CONFIG.isEphemeralKeyCompressed
      ? COMPRESSED_PUBLIC_KEY_SIZE
      : UNCOMPRESSED_PUBLIC_KEY_SIZE,
    x25519: CURVE25519_PUBLIC_KEY_SIZE,
    ed25519: CURVE25519_PUBLIC_KEY_SIZE,
  };

  if (ECIES_CONFIG.ellipticCurve in mapping) {
    return mapping[ECIES_CONFIG.ellipticCurve];
  } else {
    /* v8 ignore next 2 */
    throw new Error("Not implemented");
  }
};
