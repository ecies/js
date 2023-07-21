import { xchacha20_poly1305 as xchacha20 } from "@noble/ciphers/chacha";
import { Cipher } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto/utils";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { createCipheriv, createDecipheriv } from "crypto";

import { NonceLength, symmetricAlgorithm, symmetricNonceLength } from "../config";
import { AEAD_TAG_LENGTH, XCHACHA20_NONCE_LENGTH } from "../consts";

function _aesEncrypt(key: Buffer, plainText: Buffer, nonceLength: NonceLength): Buffer {
  const nonce = randomBytes(nonceLength);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, tag, encrypted]);
}

function _aesDecrypt(
  key: Buffer,
  cipherText: Buffer,
  nonceLength: NonceLength
): Buffer {
  const nonceTagLength = nonceLength + AEAD_TAG_LENGTH;
  const nonce = cipherText.subarray(0, nonceLength);
  const tag = cipherText.subarray(nonceLength, nonceTagLength);
  const ciphered = cipherText.subarray(nonceTagLength);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphered), decipher.final()]);
}

function _encrypt(
  func: (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher,
  key: Buffer,
  plainText: Buffer,
  nonceLength: number
) {
  const nonce = randomBytes(nonceLength);
  const cipher = func(key, nonce);
  const ciphered = cipher.encrypt(plainText);
  const encrypted = ciphered.subarray(0, ciphered.length - AEAD_TAG_LENGTH);
  const tag = ciphered.subarray(-AEAD_TAG_LENGTH);
  return Buffer.concat([nonce, tag, encrypted]);
}

function _decrypt(
  func: (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher,
  key: Buffer,
  cipherText: Buffer,
  nonceLength: number
) {
  const nonceTagLength = nonceLength + AEAD_TAG_LENGTH;
  const nonce = cipherText.subarray(0, nonceLength);
  const tag = cipherText.subarray(nonceLength, nonceTagLength);
  const ciphered = cipherText.subarray(nonceTagLength);

  const decipher = func(key, nonce);
  const res = new Uint8Array(AEAD_TAG_LENGTH + ciphered.length);
  res.set(ciphered);
  res.set(tag, ciphered.length);
  return Buffer.from(decipher.decrypt(res));
}

export function aesEncrypt(key: Buffer, plainText: Buffer): Buffer {
  // TODO: Rename to symEncrypt
  const algorithm = symmetricAlgorithm();
  if (algorithm === "aes-256-gcm") {
    return _aesEncrypt(key, plainText, symmetricNonceLength());
  } else if (algorithm === "xchacha20") {
    return _encrypt(xchacha20, key, plainText, XCHACHA20_NONCE_LENGTH);
  } else {
    throw new Error("Not implemented");
  }
}

export function aesDecrypt(key: Buffer, cipherText: Buffer): Buffer {
  // TODO: Rename to symDecrypt
  const algorithm = symmetricAlgorithm();
  if (algorithm === "aes-256-gcm") {
    return _aesDecrypt(key, cipherText, symmetricNonceLength());
  } else if (algorithm === "xchacha20") {
    return _decrypt(xchacha20, key, cipherText, XCHACHA20_NONCE_LENGTH);
  } else {
    throw new Error("Not implemented");
  }
}

export function deriveKey(master: Buffer) {
  // 32 bytes shared secret for aes and chacha20
  return Buffer.from(hkdf(sha256, master, undefined, undefined, 32));
}
