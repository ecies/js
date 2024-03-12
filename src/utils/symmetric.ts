import { xchacha20poly1305 as xchacha20 } from "@noble/ciphers/chacha";
import { Cipher, concatBytes } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import { symmetricAlgorithm, symmetricNonceLength } from "../config";
import { AEAD_TAG_LENGTH, XCHACHA20_NONCE_LENGTH } from "../consts";
import { aes256cbc, aes256gcm } from "./compat";

export const symEncrypt = (key: Uint8Array, plainText: Uint8Array): Uint8Array =>
  _exec(true, key, plainText);

export const symDecrypt = (key: Uint8Array, cipherText: Uint8Array): Uint8Array =>
  _exec(false, key, cipherText);

/** @deprecated - use `symEncrypt` instead. */
export const aesEncrypt = symEncrypt; // TODO: delete

/** @deprecated - use `symDecrypt` instead. */
export const aesDecrypt = symDecrypt; // TODO: delete

export const deriveKey = (master: Uint8Array): Uint8Array =>
  // 32 bytes shared secret for aes256 and xchacha20 derived from HKDF-SHA256
  hkdf(sha256, master, undefined, undefined, 32);

function _exec(is_encryption: boolean, key: Uint8Array, data: Uint8Array): Uint8Array {
  const algorithm = symmetricAlgorithm();
  const callback = is_encryption ? _encrypt : _decrypt;
  if (algorithm === "aes-256-gcm") {
    return callback(aes256gcm, key, data, symmetricNonceLength());
  } else if (algorithm === "xchacha20") {
    return callback(xchacha20, key, data, XCHACHA20_NONCE_LENGTH);
  } else if (algorithm === "aes-256-cbc") {
    // aes-256-cbc is always 16 bytes iv and there is no AEAD tag
    return callback(aes256cbc, key, data, 16, 0);
  } else {
    throw new Error("Not implemented");
  }
}

function _encrypt(
  func: (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher,
  key: Uint8Array,
  plainText: Uint8Array,
  nonceLength: 12 | 16 | 24,
  tagLength: 16 | 0 = AEAD_TAG_LENGTH
): Uint8Array {
  const nonce = randomBytes(nonceLength);
  const cipher = func(key, nonce);
  const ciphered = cipher.encrypt(plainText); // encrypted || tag

  const encrypted = ciphered.subarray(0, ciphered.length - tagLength);
  const tag = ciphered.subarray(ciphered.length - tagLength);
  return concatBytes(nonce, tag, encrypted);
}

function _decrypt(
  func: (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher,
  key: Uint8Array,
  cipherText: Uint8Array,
  nonceLength: 12 | 16 | 24,
  tagLength: 16 | 0 = AEAD_TAG_LENGTH
): Uint8Array {
  const nonceTagLength = nonceLength + tagLength;
  const nonce = cipherText.subarray(0, nonceLength);
  const tag = cipherText.subarray(nonceLength, nonceTagLength);
  const encrypted = cipherText.subarray(nonceTagLength);

  const decipher = func(key, Uint8Array.from(nonce)); // to reset byteOffset
  const ciphered = concatBytes(encrypted, tag);
  return decipher.decrypt(ciphered);
}
