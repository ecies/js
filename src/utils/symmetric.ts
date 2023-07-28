import { xchacha20_poly1305 as xchacha20 } from "@noble/ciphers/chacha";
import { Cipher } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto/utils";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { createCipheriv, createDecipheriv } from "crypto";

import { NonceLength, symmetricAlgorithm, symmetricNonceLength } from "../config";
import { AEAD_TAG_LENGTH, XCHACHA20_NONCE_LENGTH } from "../consts";

function _aesEncrypt(
  key: Uint8Array,
  plainText: Uint8Array,
  nonceLength: NonceLength
): Uint8Array {
  const nonce = randomBytes(nonceLength);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);

  const updated = cipher.update(plainText);
  const finalized = cipher.final();
  const tag = cipher.getAuthTag();

  const payload = new Uint8Array(
    nonce.length + tag.length + updated.length + finalized.length
  );
  payload.set(nonce);
  payload.set(tag, nonce.length);
  payload.set(updated, nonce.length + tag.length);
  payload.set(finalized, nonce.length + tag.length + updated.length);
  return payload;
}

function _aesDecrypt(
  key: Uint8Array,
  cipherText: Uint8Array,
  nonceLength: NonceLength
): Uint8Array {
  const nonceTagLength = nonceLength + AEAD_TAG_LENGTH;
  const nonce = cipherText.subarray(0, nonceLength);
  const tag = cipherText.subarray(nonceLength, nonceTagLength);
  const ciphered = cipherText.subarray(nonceTagLength);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);

  const updated = decipher.update(ciphered);
  const finalized = decipher.final();

  const payload = new Uint8Array(updated.length + finalized.length);
  payload.set(updated);
  payload.set(finalized, updated.length);
  return payload;
}

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

  const payload = new Uint8Array(nonce.length + tag.length + encrypted.length);
  payload.set(nonce);
  payload.set(tag, nonce.length);
  payload.set(encrypted, nonce.length + tag.length);
  return payload;
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

  const ciphered = new Uint8Array(encrypted.length + AEAD_TAG_LENGTH);
  ciphered.set(encrypted);
  ciphered.set(tag, encrypted.length);
  return decipher.decrypt(ciphered);
}

export function aesEncrypt(key: Uint8Array, plainText: Uint8Array): Buffer {
  // TODO: Rename to symEncrypt
  const algorithm = symmetricAlgorithm();
  if (algorithm === "aes-256-gcm") {
    return Buffer.from(_aesEncrypt(key, plainText, symmetricNonceLength()));
  } else if (algorithm === "xchacha20") {
    return Buffer.from(_encrypt(xchacha20, key, plainText, XCHACHA20_NONCE_LENGTH));
  } else {
    throw new Error("Not implemented");
  }
}

export function aesDecrypt(key: Uint8Array, cipherText: Uint8Array): Buffer {
  // TODO: Rename to symDecrypt
  const algorithm = symmetricAlgorithm();
  if (algorithm === "aes-256-gcm") {
    return Buffer.from(_aesDecrypt(key, cipherText, symmetricNonceLength()));
  } else if (algorithm === "xchacha20") {
    return Buffer.from(_decrypt(xchacha20, key, cipherText, XCHACHA20_NONCE_LENGTH));
  } else {
    throw new Error("Not implemented");
  }
}

export function deriveKey(master: Uint8Array): Buffer {
  // 32 bytes shared secret for aes and chacha20
  return Buffer.from(hkdf(sha256, master, undefined, undefined, 32));
}
