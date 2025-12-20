/**
 * ChaCha cipher implementations using @noble/ciphers.
 * Pure JavaScript fallback for browsers, React Native, Deno, and Bun.
 */
import { chacha20poly1305, xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import type { Cipher } from "@noble/ciphers/utils.js";

export const xchacha20 = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  xchacha20poly1305(key, nonce, AAD);

export const chacha20 = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  chacha20poly1305(key, nonce, AAD);
