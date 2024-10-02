import { decodeHex, remove0x } from "../../src/utils";

describe("test hex", () => {
  it("removes 0x", () => {
    expect(remove0x("0011")).toBe("0011");
    expect(remove0x("0022")).toBe("0022");
    expect(remove0x("0x0011")).toBe("0011");
    expect(remove0x("0X0022")).toBe("0022");
  });

  it("converts hex to buffer", () => {
    expect(decodeHex("0x0011")).toEqual(Uint8Array.from([0, 0x11]));
    expect(decodeHex("0X0022")).toEqual(Uint8Array.from([0, 0x22]));
  });
});
