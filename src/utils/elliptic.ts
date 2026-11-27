import { randomBytes } from "@noble/ciphers/webcrypto";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";

import type { EllipticCurve } from "../config.js";
import { ETH_PUBLIC_KEY_SIZE, SECRET_KEY_LENGTH } from "../consts.js";
import { decodeHex } from "./hex.js";

export const getValidSecret = (curve: EllipticCurve): Uint8Array => {
  let key: Uint8Array;
  do {
    key = randomBytes(SECRET_KEY_LENGTH);
  } while (!isValidPrivateKey(curve, key));
  return key;
};

export const isValidPrivateKey = (curve: EllipticCurve, secret: Uint8Array): boolean =>
  // on secp256k1: only key ∈ (0, group order) is valid
  // on curve25519: any 32-byte key is valid
  _exec(
    curve,
    (curve) => curve.utils.isValidSecretKey(secret),
    () => true,
    () => true
  );

export const getPublicKey = (curve: EllipticCurve, secret: Uint8Array): Uint8Array =>
  _exec(
    curve,
    (curve) => curve.getPublicKey(secret),
    (curve) => curve.getPublicKey(secret),
    (curve) => getExtendedPublicKeyOnEd25519(curve, secret).pointBytes
  );

export const getSharedPoint = (
  curve: EllipticCurve,
  sk: Uint8Array,
  pk: Uint8Array,
  compressed?: boolean
): Uint8Array =>
  _exec(
    curve,
    (curve) => curve.getSharedSecret(sk, pk, compressed),
    (curve) => curve.getSharedSecret(sk, pk),
    (curve) => getSharedPointOnEd25519(curve, sk, pk)
  );

export const convertPublicKeyFormat = (
  curve: EllipticCurve,
  pk: Uint8Array,
  compressed: boolean
): Uint8Array =>
  // only for secp256k1
  _exec(
    curve,
    // fromBytes refuses any point getSharedSecret would refuse, so encoding it again needs no
    // scalar multiplication
    (curve) => curve.Point.fromBytes(pk).toBytes(compressed),
    () => pk,
    () => pk
  );

export const hexToPublicKey = (curve: EllipticCurve, hex: string): Uint8Array => {
  const decoded = decodeHex(hex);
  return _exec(
    curve,
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
  const _curve = curve;
  /* v8 ignore else -- @preserve */
  if (_curve === "secp256k1") {
    return secp256k1Callback(secp256k1);
  } else if (_curve === "x25519") {
    return x25519Callback(x25519);
  } else if (_curve === "ed25519") {
    return ed25519Callback(ed25519);
  } else {
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
  const point = curve.Point.fromBytes(pk);
  // A small-order point makes the shared point one of at most 8 that anyone can derive, and a
  // point with a small-order component makes it depend on the scalar mod 8, which decrypt then
  // leaks. Both checks are needed: the identity counts as torsion-free.
  if (point.isSmallOrder() || !point.isTorsionFree()) {
    throw new Error("Invalid public key");
  }
  const { scalar } = getExtendedPublicKeyOnEd25519(curve, sk);
  return point.multiply(scalar).toBytes();
};

// The scalar and public key that RFC 8032 hashes from an ed25519 secret key. Best effort: the
// two halves of the hash that noble returns are wiped, since head is the scalar's bytes, which
// give every shared point, and prefix is the EdDSA nonce key. noble's own copies of the hash
// are out of reach.
const getExtendedPublicKeyOnEd25519 = (
  curve: typeof ed25519,
  sk: Uint8Array
): { scalar: bigint; pointBytes: Uint8Array } => {
  const { head, prefix, scalar, pointBytes } = curve.utils.getExtendedPublicKey(sk);
  head.fill(0);
  prefix.fill(0);
  return { scalar, pointBytes };
};
