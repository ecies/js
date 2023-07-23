import { COMPRESSED_PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE } from "./consts";

export type SymmetricAlgorithm = "aes-256-gcm" | "xchacha20";
export type NonceLength = 12 | 16; // bytes. Only for aes-256-gcm

class Config {
  isEphemeralKeyCompressed: boolean = false;
  isHkdfKeyCompressed: boolean = false;
  symmetricAlgorithm: SymmetricAlgorithm = "aes-256-gcm";
  symmetricNonceLength: NonceLength = 16;
}

export const ECIES_CONFIG = new Config();

export const isEphemeralKeyCompressed = () => ECIES_CONFIG.isEphemeralKeyCompressed;
export const isHkdfKeyCompressed = () => ECIES_CONFIG.isHkdfKeyCompressed;
export const ephemeralKeySize = () =>
  ECIES_CONFIG.isEphemeralKeyCompressed
    ? COMPRESSED_PUBLIC_KEY_SIZE
    : UNCOMPRESSED_PUBLIC_KEY_SIZE;
export const symmetricAlgorithm = () => ECIES_CONFIG.symmetricAlgorithm;
export const symmetricNonceLength = () => ECIES_CONFIG.symmetricNonceLength;
