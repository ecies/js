import { concatBytes } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto/utils";
import { secp256k1 } from "@noble/curves/secp256k1";

import { SECRET_KEY_LENGTH } from "../consts";
import { deriveKey } from "./symmetric";

export function isValidPrivateKey(secret: Uint8Array) {
  return secp256k1.utils.isValidPrivateKey(secret);
}

export function getValidSecret(): Uint8Array {
  let key: Uint8Array;
  do {
    key = randomBytes(SECRET_KEY_LENGTH);
  } while (!isValidPrivateKey(key));
  return key;
}

export function getPublicKey(secret: Uint8Array): Uint8Array {
  return secp256k1.getPublicKey(secret);
}

export function getSharedPoint(
  skRaw: Uint8Array | bigint,
  pkRaw: Uint8Array,
  compressed: boolean
): Uint8Array {
  return secp256k1.getSharedSecret(skRaw, pkRaw, compressed);
}

export function getSharedKey(
  ephemeralSenderPoint: Uint8Array,
  sharedPoint: Uint8Array
): Uint8Array {
  return deriveKey(concatBytes(ephemeralSenderPoint, sharedPoint));
}
