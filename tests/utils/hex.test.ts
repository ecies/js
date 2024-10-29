import { describe, expect, it } from "vitest";

import { decodeHex, remove0x } from "../../src/utils";

describe("test hex", () => {
  it("removes 0x", () => {
    expect(remove0x("0011")).toBe("0011");
    expect(remove0x("0022")).toBe("0022");
    expect(remove0x("0x0011")).toBe("0011");
    expect(remove0x("0X0022")).toBe("0022");
  });

  it("converts hex string to Uint8Array", () => {
    expect(decodeHex("0x0011")).toStrictEqual(Uint8Array.from([0, 0x11]));
    expect(decodeHex("0X0022")).toStrictEqual(Uint8Array.from([0, 0x22]));
  });
});
