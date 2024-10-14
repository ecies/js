import { Cipher, concatBytes } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto";

import { aes256cbc, aes256gcm } from "@ecies/ciphers/aes";
import { xchacha20 } from "@ecies/ciphers/chacha";
import { symmetricAlgorithm, symmetricNonceLength } from "../config";
import { AEAD_TAG_LENGTH, XCHACHA20_NONCE_LENGTH } from "../consts";

export const symEncrypt = (key: Uint8Array, plainText: Uint8Array): Uint8Array =>
  _exec(_encrypt, key, plainText);

export const symDecrypt = (key: Uint8Array, cipherText: Uint8Array): Uint8Array =>
  _exec(_decrypt, key, cipherText);

/** @deprecated - use `symEncrypt` instead. */
export const aesEncrypt = symEncrypt; // TODO: delete

/** @deprecated - use `symDecrypt` instead. */
export const aesDecrypt = symDecrypt; // TODO: delete

function _exec(
  callback: typeof _encrypt | typeof _decrypt,
  key: Uint8Array,
  data: Uint8Array
): Uint8Array {
  const algorithm = symmetricAlgorithm();
  if (algorithm === "aes-256-gcm") {
    return callback(aes256gcm, key, data, symmetricNonceLength(), AEAD_TAG_LENGTH);
  } else if (algorithm === "xchacha20") {
    return callback(xchacha20, key, data, XCHACHA20_NONCE_LENGTH, AEAD_TAG_LENGTH);
  } else if (algorithm === "aes-256-cbc") {
    // NOT RECOMMENDED. There is neither AAD nor AEAD tag in cbc mode
    // aes-256-cbc always uses 16 bytes iv
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
  tagLength: 16 | 0
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
  tagLength: 16 | 0
): Uint8Array {
  const nonceTagLength = nonceLength + tagLength;
  const nonce = cipherText.subarray(0, nonceLength);
  const tag = cipherText.subarray(nonceLength, nonceTagLength);
  const encrypted = cipherText.subarray(nonceTagLength);

  const decipher = func(key, Uint8Array.from(nonce)); // to reset byteOffset
  const ciphered = concatBytes(encrypted, tag);
  return decipher.decrypt(ciphered);
}
