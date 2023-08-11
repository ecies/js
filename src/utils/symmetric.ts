import { xchacha20poly1305 as xchacha20 } from "@noble/ciphers/chacha";
import { Cipher, concatBytes } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto/utils";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import { symmetricAlgorithm, symmetricNonceLength } from "../config";
import { AEAD_TAG_LENGTH, XCHACHA20_NONCE_LENGTH } from "../consts";
import { aes256gcm } from "./compat";

function _encrypt(
  func: (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher,
  key: Uint8Array,
  plainText: Uint8Array,
  nonceLength: number
): Uint8Array {
  const nonce = randomBytes(nonceLength);
  const cipher = func(key, nonce);
  const ciphered = cipher.encrypt(plainText); // TAG + encrypted

  const encrypted = ciphered.subarray(0, ciphered.length - AEAD_TAG_LENGTH);
  const tag = ciphered.subarray(-AEAD_TAG_LENGTH);
  return concatBytes(nonce, tag, encrypted);
}

function _decrypt(
  func: (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher,
  key: Uint8Array,
  cipherText: Uint8Array,
  nonceLength: number
): Uint8Array {
  const nonceTagLength = nonceLength + AEAD_TAG_LENGTH;
  const nonce = cipherText.subarray(0, nonceLength);
  const tag = cipherText.subarray(nonceLength, nonceTagLength);
  const encrypted = cipherText.subarray(nonceTagLength);

  const decipher = func(key, Uint8Array.from(nonce)); // to reset byteOffset
  const ciphered = concatBytes(encrypted, tag);
  return decipher.decrypt(ciphered);
}

export function aesEncrypt(key: Uint8Array, plainText: Uint8Array): Uint8Array {
  // TODO: Rename to symEncrypt
  const algorithm = symmetricAlgorithm();
  if (algorithm === "aes-256-gcm") {
    return _encrypt(aes256gcm, key, plainText, symmetricNonceLength());
  } else if (algorithm === "xchacha20") {
    return _encrypt(xchacha20, key, plainText, XCHACHA20_NONCE_LENGTH);
  } else {
    throw new Error("Not implemented");
  }
}

export function aesDecrypt(key: Uint8Array, cipherText: Uint8Array): Uint8Array {
  // TODO: Rename to symDecrypt
  const algorithm = symmetricAlgorithm();
  if (algorithm === "aes-256-gcm") {
    return _decrypt(aes256gcm, key, cipherText, symmetricNonceLength());
  } else if (algorithm === "xchacha20") {
    return _decrypt(xchacha20, key, cipherText, XCHACHA20_NONCE_LENGTH);
  } else {
    throw new Error("Not implemented");
  }
}

export function deriveKey(master: Uint8Array): Uint8Array {
  // 32 bytes shared secret for aes and chacha20
  return hkdf(sha256, master, undefined, undefined, 32);
}
