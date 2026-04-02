import { concatBytes } from "@noble/ciphers/utils";

import { type Config, ECIES_CONFIG } from "./config.js";
import { PrivateKey, PublicKey } from "./keys/index.js";

import { symDecrypt, symEncrypt } from "./utils/index.js";

/**
 * Encrypts data with a receiver's public key.
 * @description
 * In version 0.4.18, `Buffer` is returned when available, otherwise `Uint8Array`.
 * From version 0.5.0, this function will always return `Uint8Array`.
 * To preserve the pre-0.5.0 behavior of returning a `Buffer`, wrap the result with `Buffer.from(encrypt(...))`.
 *
 * @param receiverRawPK - Raw public key of the receiver, either as a hex `string` or a `Uint8Array`.
 * @param data - Data to encrypt.
 * @returns Encrypted payload, format: `public key || encrypted`.
 */
export function encrypt(
  receiverRawPK: string | Uint8Array,
  data: Uint8Array,
  config: Config = ECIES_CONFIG
): Uint8Array {
  const curve = config.ellipticCurve;
  const ephemeralSK = new PrivateKey(undefined, curve);

  const receiverPK =
    receiverRawPK instanceof Uint8Array
      ? new PublicKey(receiverRawPK, curve)
      : PublicKey.fromHex(receiverRawPK, curve);

  const sharedKey = ephemeralSK.encapsulate(receiverPK, config.isHkdfKeyCompressed);
  const ephemeralPK = ephemeralSK.publicKey.toBytes(config.isEphemeralKeyCompressed);

  const encrypted = symEncrypt(config, sharedKey, data);
  return concatBytes(ephemeralPK, encrypted);
}

/**
 * Decrypts data with a receiver's private key.
 * @description
 * In version 0.4.18, `Buffer` is returned when available, otherwise `Uint8Array`.
 * From version 0.5.0, this function will always return `Uint8Array`.
 * To preserve the pre-0.5.0 behavior of returning a `Buffer`, wrap the result with `Buffer.from(decrypt(...))`.
 *
 * @param receiverRawSK - Raw private key of the receiver, either as a hex `string` or a `Uint8Array`.
 * @param data - Data to decrypt.
 * @returns Decrypted plain text.
 */
export function decrypt(
  receiverRawSK: string | Uint8Array,
  data: Uint8Array,
  config: Config = ECIES_CONFIG
): Uint8Array {
  const curve = config.ellipticCurve;

  const receiverSK =
    receiverRawSK instanceof Uint8Array
      ? new PrivateKey(receiverRawSK, curve)
      : PrivateKey.fromHex(receiverRawSK, curve);

  const keySize = config.ephemeralKeySize;
  const ephemeralPK = new PublicKey(data.subarray(0, keySize), curve);
  const encrypted = data.subarray(keySize);
  const sharedKey = ephemeralPK.decapsulate(receiverSK, config.isHkdfKeyCompressed);
  return symDecrypt(config, sharedKey, encrypted);
}

export { ECIES_CONFIG } from "./config.js";
export { PrivateKey, PublicKey } from "./keys/index.js";
