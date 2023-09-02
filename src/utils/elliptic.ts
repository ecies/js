import { concatBytes } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto/utils";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";

import { ellipticCurve } from "../config";
import { ETH_PUBLIC_KEY_SIZE, SECRET_KEY_LENGTH } from "../consts";
import { decodeHex } from "./hex";
import { deriveKey } from "./symmetric";

export function getValidSecret(): Uint8Array {
  let key: Uint8Array;
  do {
    key = randomBytes(SECRET_KEY_LENGTH);
  } while (!isValidPrivateKey(key));
  return key;
}

export function isValidPrivateKey(secret: Uint8Array): boolean {
  // only key in (0, group order) is valid on secp256k1
  // any 32-byte key is valid on curve25519
  return toCurve(
    (curve) => curve.utils.isValidPrivateKey(secret),
    () => true,
    () => true
  );
}

export function getPublicKey(secret: Uint8Array): Uint8Array {
  return toCurve(
    (curve) => curve.getPublicKey(secret),
    (curve) => curve.getPublicKey(secret),
    (curve) => curve.getPublicKey(secret)
  );
}

export function getSharedKey(
  ephemeralSenderPoint: Uint8Array,
  sharedPoint: Uint8Array
): Uint8Array {
  return deriveKey(concatBytes(ephemeralSenderPoint, sharedPoint));
}

export function getSharedPoint(
  skRaw: Uint8Array,
  pkRaw: Uint8Array,
  compressed?: boolean
): Uint8Array {
  return toCurve(
    (curve) => curve.getSharedSecret(skRaw, pkRaw, compressed),
    (curve) => curve.getSharedSecret(skRaw, pkRaw),
    (curve) => {
      // Note: scalar is hashed from skRaw
      const { scalar } = curve.utils.getExtendedPublicKey(skRaw);
      const point = curve.ExtendedPoint.fromHex(pkRaw).multiply(scalar);
      return point.toRawBytes();
    }
  );
}

export function convertPublicKeyFormat(
  pkRaw: Uint8Array,
  compressed: boolean
): Uint8Array {
  return toCurve(
    (curve) => curve.getSharedSecret(BigInt(1), pkRaw, compressed), // only for secp256k1
    () => pkRaw,
    () => pkRaw
  );
}

export function hexToPublicKey(hex: string): Uint8Array {
  const decoded = decodeHex(hex);
  return toCurve(
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
}

function toCurve<T>(
  secp256k1Callback: (curve: typeof secp256k1) => T,
  x25519Callback: (curve: typeof x25519) => T,
  ed25519Callback: (curve: typeof ed25519) => T
) {
  if (ellipticCurve() === "secp256k1") {
    return secp256k1Callback(secp256k1);
  } else if (ellipticCurve() === "x25519") {
    return x25519Callback(x25519);
  } else if (ellipticCurve() === "ed25519") {
    return ed25519Callback(ed25519);
  } else {
    throw new Error("Not implemented");
  }
}
