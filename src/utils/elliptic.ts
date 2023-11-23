import { concatBytes } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto/utils";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";

import { ellipticCurve } from "../config";
import { ETH_PUBLIC_KEY_SIZE, SECRET_KEY_LENGTH } from "../consts";
import { decodeHex } from "./hex";
import { deriveKey } from "./symmetric";

export const isValidPrivateKey = (secret: Uint8Array): boolean =>
  // on secp256k1: only key ∈ (0, group order) is valid
  // on curve25519: any 32-byte key is valid
  _exec(
    (curve) => curve.utils.isValidPrivateKey(secret),
    () => true,
    () => true
  );

export const getValidSecret = (): Uint8Array => {
  let key: Uint8Array;
  do {
    key = randomBytes(SECRET_KEY_LENGTH);
  } while (!isValidPrivateKey(key));
  return key;
};

export const getPublicKey = (secret: Uint8Array): Uint8Array =>
  _exec(
    (curve) => curve.getPublicKey(secret),
    (curve) => curve.getPublicKey(secret),
    (curve) => curve.getPublicKey(secret)
  );

export const getSharedKey = (
  ephemeralPoint: Uint8Array,
  sharedPoint: Uint8Array
): Uint8Array => deriveKey(concatBytes(ephemeralPoint, sharedPoint));

export const getSharedPoint = (
  sk: Uint8Array,
  pk: Uint8Array,
  compressed?: boolean
): Uint8Array =>
  _exec(
    (curve) => curve.getSharedSecret(sk, pk, compressed),
    (curve) => curve.getSharedSecret(sk, pk),
    (curve) => {
      // Note: scalar is hashed from sk
      const { scalar } = curve.utils.getExtendedPublicKey(sk);
      const point = curve.ExtendedPoint.fromHex(pk).multiply(scalar);
      return point.toRawBytes();
    }
  );

export const convertPublicKeyFormat = (
  pk: Uint8Array,
  compressed: boolean
): Uint8Array =>
  // only for secp256k1
  _exec(
    (curve) => curve.getSharedSecret(BigInt(1), pk, compressed),
    () => pk,
    () => pk
  );

export const hexToPublicKey = (hex: string): Uint8Array => {
  const decoded = decodeHex(hex);
  return _exec(
    () => {
      if (decoded.length === ETH_PUBLIC_KEY_SIZE) {
        const fixed = new Uint8Array(1 + decoded.length);
        fixed.set([0x04]);
        fixed.set(decoded, 1);
        return fixed;
      }
      return decoded;
    },
    () => decoded,
    () => decoded
  );
};

function _exec<T>(
  secp256k1Callback: (curve: typeof secp256k1) => T,
  x25519Callback: (curve: typeof x25519) => T,
  ed25519Callback: (curve: typeof ed25519) => T
): T {
  const curve = ellipticCurve();
  if (curve === "secp256k1") {
    return secp256k1Callback(secp256k1);
  } else if (curve === "x25519") {
    return x25519Callback(x25519);
  } else if (curve === "ed25519") {
    return ed25519Callback(ed25519);
  } else {
    throw new Error("Not implemented");
  }
}
