/**
 * ChaCha cipher implementations using Node.js native crypto.
 * Provides better performance on Node.js.
 * Note: Deno/Bun don't support chacha20-poly1305 in node:crypto yet.
 */
import type { Cipher } from "@noble/ciphers/utils.js";
import { _compat } from "./_compat.js";
import { _hchacha20, u8, u32 } from "./_hchacha.js";

// "expand 32-byte k" in little-endian uint32
const CHACHA_CONSTANTS = new Uint32Array([
  0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
]);

/**
 * XChaCha20-Poly1305 using node:crypto's chacha20-poly1305 with HChaCha20 key derivation.
 */
export const xchacha20 = (
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
): Cipher => {
  if (nonce.length !== 24) {
    throw new Error("xchacha20's nonce must be 24 bytes");
  }

  const subKey = new Uint32Array(8);
  _hchacha20(CHACHA_CONSTANTS, u32(key), u32(nonce.subarray(0, 16)), subKey);

  const subNonce = new Uint8Array(12);
  subNonce.set([0, 0, 0, 0]);
  subNonce.set(nonce.subarray(16), 4);

  return _compat("chacha20-poly1305", u8(subKey), subNonce, AAD);
};

/**
 * ChaCha20-Poly1305 using node:crypto.
 */
export const chacha20 = (
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
): Cipher => {
  if (nonce.length !== 12) {
    throw new Error("chacha20's nonce must be 12 bytes");
  }
  return _compat("chacha20-poly1305", key, nonce, AAD);
};
