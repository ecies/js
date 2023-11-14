import { Cipher, concatBytes } from "@noble/ciphers/utils";
import { CipherGCM, DecipherGCM, createCipheriv, createDecipheriv } from "crypto";
import { AEAD_TAG_LENGTH } from "../consts";

export const aes256gcm = (
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
): Cipher => {
  return _compatAES("aes-256-gcm", key, nonce, AAD);
};

// NOT RECOMMENDED. There is neither AAD nor AEAD tag in cbc mode
export const aes256cbc = (
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
): Cipher => {
  return _compatAES("aes-256-cbc", key, nonce);
};

// make `node:crypto`'s aes compatible with `@noble/ciphers`
function _compatAES(
  algorithm: "aes-256-cbc" | "aes-256-gcm",
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
): Cipher {
  const isAEAD = algorithm === "aes-256-gcm";
  const tagLength = isAEAD ? AEAD_TAG_LENGTH : 0;

  const encrypt = (plainText: Uint8Array) => {
    const cipher = createCipheriv(algorithm, key, nonce);
    if (isAEAD && AAD) {
      (cipher as CipherGCM).setAAD(AAD);
    }

    const updated = cipher.update(plainText);
    const finalized = cipher.final();
    if (isAEAD) {
      return concatBytes(updated, finalized, (cipher as CipherGCM).getAuthTag());
    }
    return concatBytes(updated, finalized);
  };

  const decrypt = (cipherText: Uint8Array) => {
    const encrypted = cipherText.subarray(0, cipherText.length - tagLength);
    const tag = cipherText.subarray(cipherText.length - tagLength);

    const decipher = createDecipheriv(algorithm, key, nonce);
    if (isAEAD) {
      if (AAD) {
        (decipher as DecipherGCM).setAAD(AAD);
      }
      (decipher as DecipherGCM).setAuthTag(tag);
    }
    const updated = decipher.update(encrypted);
    const finalized = decipher.final();
    return concatBytes(updated, finalized);
  };

  return {
    encrypt,
    decrypt,
  };
}
