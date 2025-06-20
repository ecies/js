import { describe, expect, it } from "vitest";

import { PrivateKey, PublicKey } from "../../src";
import { decodeHex } from "../../src/utils";

describe("test validation", () => {
  it("tests invalid secp256k1", () => {
    // 0 < private key < group order int
    const ERROR = "Invalid private key";

    expect(() => PrivateKey.fromHex("00")).toThrow(ERROR);

    const groupOrderInt =
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
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
