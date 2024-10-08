import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

export const deriveKey = (master: Uint8Array): Uint8Array =>
  // 32 bytes shared secret for aes256 and xchacha20 derived from HKDF-SHA256
  hkdf(sha256, master, undefined, undefined, 32);
