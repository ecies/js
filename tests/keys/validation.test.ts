import { concatBytes } from "@noble/ciphers/utils";
import { ED25519_TORSION_SUBGROUP, ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";

import { decrypt, encrypt, PrivateKey, PublicKey } from "../../src";
import { Config } from "../../src/config";
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
