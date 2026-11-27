import { bytesToHex, concatBytes } from "@noble/ciphers/utils";
import { ED25519_TORSION_SUBGROUP, ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { describe, expect, it, vi } from "vitest";

import { decrypt, encrypt, PrivateKey, PublicKey } from "../../src";
import { Config, type EllipticCurve } from "../../src/config";
import { decodeHex, getSharedKey, getSharedPoint, symEncrypt } from "../../src/utils";

describe("test validation", () => {
  it("tests invalid secp256k1", () => {
    // 0 < private key < group order int
    const ERROR = "Invalid private key";

    expect(() => PrivateKey.fromHex("00")).toThrow(ERROR);

    const groupOrderInt = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    expect(() => PrivateKey.fromHex(groupOrderInt)).toThrow(ERROR);

    const groupOrderIntMinus1 =
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
    expect(PrivateKey.fromHex(groupOrderIntMinus1)).toStrictEqual(
      new PrivateKey(decodeHex(groupOrderIntMinus1))
    );

    const groupOrderIntAdd1 =
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
    expect(() => PrivateKey.fromHex(groupOrderIntAdd1)).toThrow(ERROR);

    const pk =
      "04307bac038efaa5bf8a0ac8db53fd4de8024a0c0baf37283a9e6671589eba18e" +
      "dc12b3915ff0df66e6ffad862440228a65ead99e3320e50aa90008961e3d68acc";
    expect(() => PublicKey.fromHex(pk)).toThrow("bad point: is not on curve");
  });
});

// On ed25519, a small-order key makes the shared point one of at most 8 that anyone can derive:
// a payload encrypted to such a key opens without a secret key, and one whose ephemeral key is
// the identity opens under every secret key. A key with a small-order component, an honest key
// plus a small-order point, lets decrypt leak the secret scalar mod 8 (#922).
describe("refuses small-order and mixed-order ed25519 public keys (#922)", () => {
  const ERROR = "Invalid public key";
  const config = new Config();
  config.ellipticCurve = "ed25519";
  const message = new TextEncoder().encode("secret");
  const { Point } = ed25519;
  type EdPoint = ReturnType<typeof Point.fromHex>;
  const smallOrder = ED25519_TORSION_SUBGROUP; // the 8 points of order 1, 2, 4 or 8
  const order8 = Point.fromHex(smallOrder[1]);
  const randomPoint = () =>
    Point.fromBytes(new PrivateKey(undefined, "ed25519").publicKey.toBytes());

  // a payload that decrypt opened before the fix: its shared point is the one decrypt computed
  const forge = (receiver: PrivateKey, ephemeral: EdPoint): Uint8Array => {
    const { scalar } = ed25519.utils.getExtendedPublicKey(receiver.secret);
    const shared = ephemeral.multiplyUnsafe(scalar);
    const key = getSharedKey(ephemeral.toBytes(), shared.toBytes());
    return concatBytes(ephemeral.toBytes(), symEncrypt(config, key, message));
  };

  it.each(smallOrder)("encrypt refuses the small-order recipient key %s", (pk) => {
    expect(() => encrypt(pk, message, config)).toThrow(ERROR);
  });

  it.each(smallOrder)("decrypt refuses the small-order ephemeral key %s", (pk) => {
    const receiver = new PrivateKey(undefined, "ed25519");
    const payload = forge(receiver, Point.fromHex(pk));
    expect(() => decrypt(receiver.secret, payload, config)).toThrow(ERROR);
  });

  it("encrypt refuses a mixed-order recipient key", () => {
    const recipient = randomPoint().add(order8).toBytes();
    expect(() => encrypt(recipient, message, config)).toThrow(ERROR);
  });

  it("decrypt refuses a mixed-order ephemeral key", () => {
    const receiver = new PrivateKey(undefined, "ed25519");
    const payload = forge(receiver, randomPoint().add(order8));
    expect(() => decrypt(receiver.secret, payload, config)).toThrow(ERROR);
  });

  // every entry point refuses them, not only encrypt and decrypt
  it.each([...smallOrder, "mixed"])("every entry point refuses the key %s", (key) => {
    const pk = key === "mixed" ? randomPoint().add(order8).toBytes() : decodeHex(key);
    const receiver = new PrivateKey(undefined, "ed25519");
    const publicKey = new PublicKey(pk, "ed25519");
    expect(() => getSharedPoint("ed25519", receiver.secret, pk)).toThrow(ERROR);
    // refused before the secret key is read, so a malformed one doesn't change the error
    expect(() => getSharedPoint("ed25519", new Uint8Array(31), pk)).toThrow(ERROR);
    expect(() => receiver.multiply(publicKey)).toThrow(ERROR);
    expect(() => receiver.encapsulate(publicKey)).toThrow(ERROR);
    expect(() => publicKey.decapsulate(receiver)).toThrow(ERROR);
  });

  // noble decodes strictly, so it refuses these encodings of small-order points, which ZIP 215
  // decoding accepts
  // (little-endian y with x's sign in the top bit; p = 2^255 - 19)
  it.each([
    [`01${"00".repeat(30)}80`, "x=0 and x_0=1"], // the identity (y = 1) with x's sign set
    [`ec${"ff".repeat(31)}`, "x=0 and x_0=1"], // y = p - 1, of order 2, with x's sign set
    [`ed${"ff".repeat(30)}7f`, "valid point.y"], // y = p, for y = 0
    [`ed${"ff".repeat(31)}`, "valid point.y"], // y = p, with x's sign set
    [`ee${"ff".repeat(30)}7f`, "valid point.y"], // y = p + 1, for the identity
    [`ee${"ff".repeat(31)}`, "valid point.y"], // y = p + 1, with x's sign set
  ])("refuses the non-canonical small-order key %s", (pk, error) => {
    expect(() => encrypt(pk, message, config)).toThrow(error);

    const receiver = new PrivateKey(undefined, "ed25519");
    const payload = concatBytes(decodeHex(pk), new Uint8Array(64));
    expect(() => decrypt(receiver.secret, payload, config)).toThrow(error);
  });
});

const randomPublicKey = (curve: EllipticCurve, compressed: boolean = true): Uint8Array =>
  new PrivateKey(undefined, curve).publicKey.toBytes(compressed);

// PublicKey used to re-encode a secp256k1 key by multiplying it by 1, a full scalar
// multiplication per encoding, which made encrypt and decrypt about 4x slower (#923)
describe("decodes secp256k1 public keys without a scalar multiplication (#923)", () => {
  const secretOne = decodeHex(`${"00".repeat(31)}01`);
  // the generator's coordinates
  const gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

  it.each([true, false])("gives noble's encodings, given compressed: %s", (compressed) => {
    const bytes = randomPublicKey("secp256k1", compressed);
    const point = secp256k1.Point.fromBytes(bytes);
    const pk = new PublicKey(bytes, "secp256k1");
    expect(pk.toBytes(true)).toStrictEqual(point.toBytes(true));
    expect(pk.toBytes(false)).toStrictEqual(point.toBytes(false));
  });

  it("does no scalar multiplication", () => {
    const bytes = randomPublicKey("secp256k1");
    const multiply = vi.spyOn(secp256k1.Point.prototype, "multiply");
    const multiplyUnsafe = vi.spyOn(secp256k1.Point.prototype, "multiplyUnsafe");
    try {
      expect(new PublicKey(bytes, "secp256k1").toBytes()).toStrictEqual(bytes);
      expect(multiply).not.toHaveBeenCalled();
      expect(multiplyUnsafe).not.toHaveBeenCalled();
    } finally {
      multiply.mockRestore();
      multiplyUnsafe.mockRestore();
    }
  });

  it.each([
    ["no point has this x", `02${"00".repeat(31)}05`, "is not on curve, sqrt error"],
    ["x is not below the field prime", `02${"ff".repeat(28)}fffffc2f`, "wrong x"],
    ["off the curve", `04${gx}${"00".repeat(32)}`, "bad point: is not on curve"],
    ["hybrid prefix", `06${gx}${gy}`, "bad point: got length 65"],
    ["uncompressed prefix, compressed length", `04${gx}`, "bad point: got length 33"],
    ["empty", "", "bad point: got length 0"],
  ])("refuses what getSharedSecret refuses: %s", (_, hex, error) => {
    const bytes = decodeHex(hex);
    expect(() => secp256k1.getSharedSecret(secretOne, bytes)).toThrow();
    expect(() => new PublicKey(bytes, "secp256k1")).toThrow(error);
  });
});

// getSharedSecret also took a hex string, so new PublicKey used to accept one on secp256k1,
// while x25519 and ed25519 kept whatever they were given as the key. new PrivateKey kept a hex
// string as the key on every curve, and on secp256k1 a bigint (#923)
describe("refuses keys that are not a Uint8Array (#923)", () => {
  const curves: EllipticCurve[] = ["secp256k1", "x25519", "ed25519"];
  // what an untyped caller can pass
  const notBytes = (bytes: Uint8Array) =>
    [
      bytesToHex(bytes),
      BigInt(`0x${bytesToHex(bytes)}`),
      Array.from(bytes),
      bytes.buffer,
    ] as unknown as Uint8Array[];

  it.each(curves)("PublicKey refuses them on %s; fromHex and Buffer work", (curve) => {
    const bytes = randomPublicKey(curve);
    const hex = bytesToHex(bytes);
    for (const untyped of notBytes(bytes)) {
      expect(() => new PublicKey(untyped, curve)).toThrow("Uint8Array expected");
    }

    // the ways in that stay: fromHex for hex, and any Uint8Array, such as a Node Buffer
    expect(PublicKey.fromHex(hex, curve).toHex()).toBe(hex);
    expect(PublicKey.fromHex(`0x${hex}`, curve).toHex()).toBe(hex);
    expect(new PublicKey(Buffer.from(bytes), curve).toHex()).toBe(hex);
  });

  it.each(curves)("PrivateKey refuses them on %s; fromHex and Buffer work", (curve) => {
    const secret = new PrivateKey(undefined, curve).secret;
    const hex = bytesToHex(secret);
    for (const untyped of notBytes(secret)) {
      expect(() => new PrivateKey(untyped, curve)).toThrow("Uint8Array expected");
    }

    expect(PrivateKey.fromHex(hex, curve).toHex()).toBe(hex);
    expect(PrivateKey.fromHex(`0x${hex}`, curve).toHex()).toBe(hex);
    expect(new PrivateKey(Buffer.from(secret), curve).toHex()).toBe(hex);
  });
});
