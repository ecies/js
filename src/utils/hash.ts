import { concatBytes } from "@noble/ciphers/utils.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

export const deriveKey = (
  master: Uint8Array,
  salt?: Uint8Array,
  info?: Uint8Array
): Uint8Array =>
  // 32 bytes shared secret for aes256 and xchacha20 derived from HKDF-SHA256
  hkdf(sha256, master, salt, info, 32);

export const getSharedKey = (...parts: Uint8Array[]): Uint8Array =>
  deriveKey(concatBytes(...parts));
