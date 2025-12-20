/**
 * AES cipher implementations using Node.js native crypto.
 * Provides better performance on Node.js/Deno/Bun.
 */
import type { Cipher } from "@noble/ciphers/utils.js";
import { _compat } from "./_compat.js";

export const aes256gcm = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  _compat("aes-256-gcm", key, nonce, AAD);

export const aes256cbc = (
  key: Uint8Array,
  nonce: Uint8Array,
  _AAD?: Uint8Array
): Cipher => _compat("aes-256-cbc", key, nonce);
