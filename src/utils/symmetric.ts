import { type Cipher, concatBytes } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto";

import { aes256cbc, aes256gcm } from "@ecies/ciphers/aes";
import { xchacha20 } from "@ecies/ciphers/chacha";
import { symmetricAlgorithm, symmetricNonceLength } from "../config";
import { AEAD_TAG_LENGTH, XCHACHA20_NONCE_LENGTH } from "../consts";

export const symEncrypt = (
  key: Uint8Array,
  plainText: Uint8Array,
  AAD?: Uint8Array
): Uint8Array => _exec(_encrypt, key, plainText, AAD);

export const symDecrypt = (
  key: Uint8Array,
  cipherText: Uint8Array,
  AAD?: Uint8Array
): Uint8Array => _exec(_decrypt, key, cipherText, AAD);

/** @deprecated - use `symEncrypt` instead. */
export const aesEncrypt = symEncrypt; // TODO: delete

/** @deprecated - use `symDecrypt` instead. */
export const aesDecrypt = symDecrypt; // TODO: delete

function _exec(
  callback: typeof _encrypt | typeof _decrypt,
  key: Uint8Array,
  data: Uint8Array,
  AAD?: Uint8Array
): Uint8Array {
  const algorithm = symmetricAlgorithm();
  if (algorithm === "aes-256-gcm") {
    return callback(aes256gcm, key, data, symmetricNonceLength(), AEAD_TAG_LENGTH, AAD);
  } else if (algorithm === "xchacha20") {
    return callback(xchacha20, key, data, XCHACHA20_NONCE_LENGTH, AEAD_TAG_LENGTH, AAD);
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
  data: Uint8Array,
  nonceLength: 12 | 16 | 24,
  tagLength: 16 | 0,
  AAD?: Uint8Array
): Uint8Array {
  const nonce = randomBytes(nonceLength);
  const cipher = func(key, nonce, AAD);
  // @noble/ciphers format: cipherText || tag
  const encrypted = cipher.encrypt(data);

  if (tagLength === 0) {
    return concatBytes(nonce, encrypted);
  }

  const cipherTextLength = encrypted.length - tagLength;
  const cipherText = encrypted.subarray(0, cipherTextLength);
  const tag = encrypted.subarray(cipherTextLength);
  // ecies payload format: pk || nonce || tag || cipherText
  return concatBytes(nonce, tag, cipherText);
}

function _decrypt(
  func: (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher,
  key: Uint8Array,
  data: Uint8Array,
  nonceLength: 12 | 16 | 24,
  tagLength: 16 | 0,
  AAD?: Uint8Array
): Uint8Array {
  const nonce = data.subarray(0, nonceLength);
  const cipher = func(key, Uint8Array.from(nonce), AAD); // to reset byteOffset
  const encrypted = data.subarray(nonceLength);

  if (tagLength === 0) {
    return cipher.decrypt(encrypted);
  }

  const tag = encrypted.subarray(0, tagLength);
  const cipherText = encrypted.subarray(tagLength);
  return cipher.decrypt(concatBytes(cipherText, tag));
}
