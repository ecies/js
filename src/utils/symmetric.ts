import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

import {
  NonceLength,
  SymmetricAlgorithm,
  symmetricAlgorithm,
  symmetricNonceLength,
} from "../config";
import { AEAD_TAG_LENGTH } from "../consts";

function _aesEncrypt(
  key: Buffer,
  plainText: Buffer,
  algorithm: SymmetricAlgorithm,
  nonceLength: NonceLength
): Buffer {
  const nonce = randomBytes(nonceLength);
  const cipher = createCipheriv(algorithm, key, nonce);
  const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, tag, encrypted]);
}

function _aesDecrypt(
  key: Buffer,
  cipherText: Buffer,
  algorithm: SymmetricAlgorithm,
  nonceLength: NonceLength
): Buffer {
  const nonce = cipherText.subarray(0, nonceLength);
  const tag = cipherText.subarray(nonceLength, nonceLength + AEAD_TAG_LENGTH);
  const ciphered = cipherText.subarray(nonceLength + AEAD_TAG_LENGTH);
  const decipher = createDecipheriv(algorithm, key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphered), decipher.final()]);
}

export function aesEncrypt(key: Buffer, plainText: Buffer): Buffer {
  return _aesEncrypt(key, plainText, symmetricAlgorithm(), symmetricNonceLength());
}

export function aesDecrypt(key: Buffer, cipherText: Buffer): Buffer {
  return _aesDecrypt(key, cipherText, symmetricAlgorithm(), symmetricNonceLength());
}
export function deriveKey(master: Buffer) {
  return Buffer.from(hkdf(sha256, master, undefined, undefined, 32));
}
