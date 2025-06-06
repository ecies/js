import { randomBytes } from "@noble/ciphers/webcrypto";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";

import { type EllipticCurve, ellipticCurve } from "../config";
import { ETH_PUBLIC_KEY_SIZE, SECRET_KEY_LENGTH } from "../consts";
import { decodeHex } from "./hex";

// TODO: remove `ellipticCurve` after 0.5.0

export const getValidSecret = (curve?: EllipticCurve): Uint8Array => {
  let key: Uint8Array;
  do {
    key = randomBytes(SECRET_KEY_LENGTH);
  } while (!isValidPrivateKey(key, curve));
  return key;
};

export const isValidPrivateKey = (secret: Uint8Array, curve?: EllipticCurve): boolean =>
  // on secp256k1: only key ∈ (0, group order) is valid
  // on curve25519: any 32-byte key is valid
  _exec(
    curve || ellipticCurve(),
    (curve) => curve.utils.isValidPrivateKey(secret),
    () => true,
    () => true
  );

export const getPublicKey = (secret: Uint8Array, curve?: EllipticCurve): Uint8Array =>
  _exec(
    curve || ellipticCurve(),
    (curve) => curve.getPublicKey(secret),
    (curve) => curve.getPublicKey(secret),
    (curve) => curve.getPublicKey(secret)
  );

export const getSharedPoint = (
  sk: Uint8Array,
  pk: Uint8Array,
  compressed?: boolean,
  curve?: EllipticCurve
): Uint8Array =>
  _exec(
    curve || ellipticCurve(),
    (curve) => curve.getSharedSecret(sk, pk, compressed),
    (curve) => curve.getSharedSecret(sk, pk),
    (curve) => getSharedPointOnEd25519(curve, sk, pk)
  );

export const convertPublicKeyFormat = (
  pk: Uint8Array,
  compressed: boolean,
  curve?: EllipticCurve
): Uint8Array =>
  // only for secp256k1
  _exec(
    curve || ellipticCurve(),
    (curve) => curve.getSharedSecret(BigInt(1), pk, compressed),
    () => pk,
    () => pk
  );

export const hexToPublicKey = (hex: string, curve?: EllipticCurve): Uint8Array => {
  const decoded = decodeHex(hex);
  return _exec(
    curve || ellipticCurve(),
    () => compatEthPublicKey(decoded),
    () => decoded,
    () => decoded
  );
};

function _exec<T>(
  curve: EllipticCurve,
  secp256k1Callback: (curveFn: typeof secp256k1) => T,
  x25519Callback: (curveFn: typeof x25519) => T,
  ed25519Callback: (curveFn: typeof ed25519) => T
): T {
  if (curve === "secp256k1") {
    return secp256k1Callback(secp256k1);
  } else if (curve === "x25519") {
    return x25519Callback(x25519);
  } else if (curve === "ed25519") {
    return ed25519Callback(ed25519);
  } /* v8 ignore next 2 */ else {
    throw new Error("Not implemented");
  }
}

const compatEthPublicKey = (pk: Uint8Array): Uint8Array => {
  if (pk.length === ETH_PUBLIC_KEY_SIZE) {
    const fixed = new Uint8Array(1 + pk.length);
    fixed.set([0x04]);
    fixed.set(pk, 1);
    return fixed;
  }
  return pk;
};

const getSharedPointOnEd25519 = (
  curve: typeof ed25519,
  sk: Uint8Array,
  pk: Uint8Array
): Uint8Array => {
  // Note: scalar is hashed from sk
  const { scalar } = curve.utils.getExtendedPublicKey(sk);
  const point = curve.ExtendedPoint.fromHex(pk).multiply(scalar);
  return point.toRawBytes(); // `compressed` in signature has no effect
};
