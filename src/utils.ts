import { secp256k1 } from "@noble/curves/secp256k1";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

import { AES_IV_LENGTH, AES_IV_PLUS_TAG_LENGTH, SECRET_KEY_LENGTH } from "./consts";

export function remove0x(hex: string): string {
  if (hex.startsWith("0x") || hex.startsWith("0X")) {
    return hex.slice(2);
  }
  return hex;
}

export function decodeHex(hex: string): Buffer {
  return Buffer.from(remove0x(hex), "hex");
}

export function getValidSecret(): Buffer {
  let key: Buffer;
  do {
    key = randomBytes(SECRET_KEY_LENGTH);
  } while (!secp256k1.utils.isValidPrivateKey(key));
  return key;
}

export function aesEncrypt(key: Buffer, plainText: Buffer): Buffer {
  const nonce = randomBytes(AES_IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, tag, encrypted]);
}

export function aesDecrypt(key: Buffer, cipherText: Buffer): Buffer {
  const nonce = cipherText.subarray(0, AES_IV_LENGTH);
  const tag = cipherText.subarray(AES_IV_LENGTH, AES_IV_PLUS_TAG_LENGTH);
  const ciphered = cipherText.subarray(AES_IV_PLUS_TAG_LENGTH);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphered), decipher.final()]);
}
