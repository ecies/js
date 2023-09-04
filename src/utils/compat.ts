import { Cipher, concatBytes } from "@noble/ciphers/utils";
import { createCipheriv, createDecipheriv } from "crypto";

import { AEAD_TAG_LENGTH } from "../consts";

// make `node:crypto`'s aes compatible with `@noble/ciphers`
export function aes256gcm(
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
): Cipher {
  const encrypt = (plainText: Uint8Array) => {
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    if (AAD) {
      cipher.setAAD(AAD);
    }
    const updated = cipher.update(plainText);
    const finalized = cipher.final();
    return concatBytes(updated, finalized, cipher.getAuthTag());
  };

  const decrypt = (cipherText: Uint8Array) => {
    const encrypted = cipherText.subarray(0, cipherText.length - AEAD_TAG_LENGTH);
    const tag = cipherText.subarray(-AEAD_TAG_LENGTH);

    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    if (AAD) {
      decipher.setAAD(AAD);
    }
    decipher.setAuthTag(tag);
    const updated = decipher.update(encrypted);
    const finalized = decipher.final();
    return concatBytes(updated, finalized);
  };

  return {
    tagLength: AEAD_TAG_LENGTH,
    encrypt,
    decrypt,
  };
}
