import { aes256gcm } from "@ecies/ciphers/aes";
import { xchacha20 } from "@ecies/ciphers/chacha";
import { type Cipher, concatBytes } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto";

import type { Config } from "../config.js";
import { AEAD_TAG_LENGTH, XCHACHA20_NONCE_LENGTH } from "../consts.js";

export const symEncrypt = (
  config: Config,
  key: Uint8Array,
  plainText: Uint8Array,
  AAD?: Uint8Array
): Uint8Array => _exec(_encrypt, config, key, plainText, AAD);

export const symDecrypt = (
  config: Config,
  key: Uint8Array,
  cipherText: Uint8Array,
  AAD?: Uint8Array
): Uint8Array => _exec(_decrypt, config, key, cipherText, AAD);

function _exec(
  callback: typeof _encrypt | typeof _decrypt,
  config: Config,
  key: Uint8Array,
  data: Uint8Array,
  AAD?: Uint8Array
): Uint8Array {
  const algorithm = config.symmetricAlgorithm;
  if (algorithm === "aes-256-gcm") {
    return callback(aes256gcm, key, data, config.symmetricNonceLength, AEAD_TAG_LENGTH, AAD);
  } else if (algorithm === "xchacha20") {
    return callback(xchacha20, key, data, XCHACHA20_NONCE_LENGTH, AEAD_TAG_LENGTH, AAD);
  } else {
    throw new Error("Not implemented");
  }
}

function _encrypt(
  func: (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher,
  key: Uint8Array,
  data: Uint8Array,
  nonceLength: 12 | 16 | 24,
  tagLength: 16,
  AAD?: Uint8Array
): Uint8Array {
  const nonce = randomBytes(nonceLength);
  const cipher = func(key, nonce, AAD);
  // @noble/ciphers format: cipherText || tag
  const encrypted = cipher.encrypt(data);
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
  tagLength: 16,
  AAD?: Uint8Array
): Uint8Array {
  const nonce = data.subarray(0, nonceLength);
  const cipher = func(key, Uint8Array.from(nonce), AAD); // to reset byteOffset
  const encrypted = data.subarray(nonceLength);
  const tag = encrypted.subarray(0, tagLength);
  const cipherText = encrypted.subarray(tagLength);
  return cipher.decrypt(concatBytes(cipherText, tag));
}
