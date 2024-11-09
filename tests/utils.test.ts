import { describe, expect, it } from "vitest";

import secp256k1 from "secp256k1";

import { decodeHex, getValidSecret, remove0x } from "../src/utils";

describe("test string <-> buffer utils ", () => {
  it("should remove 0x", () => {
    expect(remove0x("0x0011")).toStrictEqual("0011");
    expect(remove0x("0011")).toStrictEqual("0011");
    expect(remove0x("0X0022")).toStrictEqual("0022");
    expect(remove0x("0022")).toStrictEqual("0022");
  });

  it("should generate valid secret", () => {
    const key = getValidSecret();
    expect(secp256k1.privateKeyVerify(key)).toBe(true);
  });

  it("should convert hex to buffer", () => {
    const decoded = decodeHex("0x0011");
    expect(decoded).toStrictEqual(Buffer.from([0, 0x11]));
  });
});
