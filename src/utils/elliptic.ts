import { secp256k1 } from "@noble/curves/secp256k1";
import { randomBytes } from "crypto";

import { SECRET_KEY_LENGTH } from "../consts";

export function isValidPrivateKey(secret: Buffer) {
  return secp256k1.utils.isValidPrivateKey(secret);
}

export function getValidSecret(): Buffer {
  let key: Buffer;
  do {
    key = randomBytes(SECRET_KEY_LENGTH);
  } while (!isValidPrivateKey(key));
  return key;
}

export function getPublicKey(secret: Buffer): Buffer {
  return Buffer.from(secp256k1.getPublicKey(secret));
}

export function getSharedPoint(
  skRaw: Buffer | bigint,
  pkRaw: Buffer,
  compressed: boolean
): Buffer {
  return Buffer.from(secp256k1.getSharedSecret(skRaw, pkRaw, compressed));
}
