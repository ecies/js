import { concatBytes } from "@noble/ciphers/utils";

import {
  ephemeralKeySize,
  isEphemeralKeyCompressed,
  isHkdfKeyCompressed,
} from "./config";
import { PrivateKey, PublicKey } from "./keys";
import {
  aesDecrypt,
  aesEncrypt,
  decodeHex,
  getValidSecret,
  remove0x,
  symDecrypt,
  symEncrypt,
} from "./utils";

/**
 * Encrypts a message.
 * @description From version 0.5.0, `Uint8Array` will be returned instead of `Buffer`.
 * To keep the same behavior, use `Buffer.from(encrypt(...))`.
 *
 * @param receiverRawPK - Raw public key of the receiver, either as a hex string or a Uint8Array.
 * @param msg - Message to encrypt.
 * @returns Encrypted payload, format: `public key || encrypted`.
 */
export function encrypt(receiverRawPK: string | Uint8Array, msg: Uint8Array): Buffer {
  const ephemeralSK = new PrivateKey();

  const receiverPK =
    receiverRawPK instanceof Uint8Array
      ? new PublicKey(receiverRawPK)
      : PublicKey.fromHex(receiverRawPK);

  const sharedKey = ephemeralSK.encapsulate(receiverPK, isHkdfKeyCompressed());
  const ephemeralPK = isEphemeralKeyCompressed()
    ? ephemeralSK.publicKey.compressed
    : ephemeralSK.publicKey.uncompressed;

  const encrypted = symEncrypt(sharedKey, msg);
  return Buffer.from(concatBytes(ephemeralPK, encrypted));
}

/**
 * Decrypts a message.
 * @description From version 0.5.0, `Uint8Array` will be returned instead of `Buffer`.
 * To keep the same behavior, use `Buffer.from(decrypt(...))`.
 *
 * @param receiverRawSK - Raw private key of the receiver, either as a hex string or a Uint8Array.
 * @param msg - Message to decrypt.
 * @returns Decrypted plain text.
 */
export function decrypt(receiverRawSK: string | Uint8Array, msg: Uint8Array): Buffer {
  const receiverSK =
    receiverRawSK instanceof Uint8Array
      ? new PrivateKey(receiverRawSK)
      : PrivateKey.fromHex(receiverRawSK);

  const keySize = ephemeralKeySize();
  const ephemeralPK = new PublicKey(msg.subarray(0, keySize));
  const encrypted = msg.subarray(keySize);
  const sharedKey = ephemeralPK.decapsulate(receiverSK, isHkdfKeyCompressed());
  return Buffer.from(symDecrypt(sharedKey, encrypted));
}

export { ECIES_CONFIG } from "./config";
export { PrivateKey, PublicKey } from "./keys";

/** @deprecated - use `import utils from "eciesjs/utils"` instead. */
export const utils = {
  // TODO: remove these after 0.5.0
  aesEncrypt,
  aesDecrypt,
  symEncrypt,
  symDecrypt,
  decodeHex,
  getValidSecret,
  remove0x,
};
