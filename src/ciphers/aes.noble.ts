/**
 * AES cipher implementations using @noble/ciphers.
 * Pure JavaScript fallback for browsers and React Native.
 */
import { cbc, gcm } from "@noble/ciphers/aes.js";
import type { Cipher } from "@noble/ciphers/utils.js";

export const aes256gcm = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  gcm(key, nonce, AAD);

export const aes256cbc = (
  key: Uint8Array,
  nonce: Uint8Array,
  _AAD?: Uint8Array
): Cipher => cbc(key, nonce);
