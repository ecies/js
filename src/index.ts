import { concatBytes } from "@noble/ciphers/utils";

import {
  ellipticCurve,
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
 * Encrypts data with a receiver's public key.
 * @description From version 0.5.0, `Uint8Array` will be returned instead of `Buffer`.
 * To keep the same behavior, use `Buffer.from(encrypt(...))`.
 *
 * @param receiverRawPK - Raw public key of the receiver, either as a hex `string` or a `Uint8Array`.
 * @param data - Data to encrypt.
 * @returns Encrypted payload, format: `public key || encrypted`.
 */
export function encrypt(receiverRawPK: string | Uint8Array, data: Uint8Array): Buffer {
  return Buffer.from(_encrypt(receiverRawPK, data));
}

function _encrypt(receiverRawPK: string | Uint8Array, data: Uint8Array): Uint8Array {
  const curve = ellipticCurve();
  const ephemeralSK = new PrivateKey(undefined, curve);

  const receiverPK =
    receiverRawPK instanceof Uint8Array
      ? new PublicKey(receiverRawPK, curve)
      : PublicKey.fromHex(receiverRawPK, curve);

  const sharedKey = ephemeralSK.encapsulate(receiverPK, isHkdfKeyCompressed());
  const ephemeralPK = ephemeralSK.publicKey.toBytes(isEphemeralKeyCompressed());

  const encrypted = symEncrypt(sharedKey, data);
  return concatBytes(ephemeralPK, encrypted);
}

/**
 * Decrypts data with a receiver's private key.
 * @description From version 0.5.0, `Uint8Array` will be returned instead of `Buffer`.
 * To keep the same behavior, use `Buffer.from(decrypt(...))`.
 *
 * @param receiverRawSK - Raw private key of the receiver, either as a hex `string` or a `Uint8Array`.
 * @param data - Data to decrypt.
 * @returns Decrypted plain text.
 */
export function decrypt(receiverRawSK: string | Uint8Array, data: Uint8Array): Buffer {
  return Buffer.from(_decrypt(receiverRawSK, data));
}

function _decrypt(receiverRawSK: string | Uint8Array, data: Uint8Array): Uint8Array {
  const curve = ellipticCurve();

  const receiverSK =
    receiverRawSK instanceof Uint8Array
      ? new PrivateKey(receiverRawSK, curve)
      : PrivateKey.fromHex(receiverRawSK, curve);

  const keySize = ephemeralKeySize();
  const ephemeralPK = new PublicKey(data.subarray(0, keySize), curve);
  const encrypted = data.subarray(keySize);
  const sharedKey = ephemeralPK.decapsulate(receiverSK, isHkdfKeyCompressed());
  return symDecrypt(sharedKey, encrypted);
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
