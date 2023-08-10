import { utils } from "../../src/index";

const { decodeHex, remove0x } = utils;

describe("test hex utils", () => {
  it("should remove 0x", () => {
    expect(remove0x("0011")).toBe("0011");
    expect(remove0x("0022")).toBe("0022");
    expect(remove0x("0x0011")).toBe("0011");
    expect(remove0x("0X0022")).toBe("0022");
  });

  it("should convert hex to buffer", () => {
    const decoded = decodeHex("0x0011");
    expect(decoded).toEqual(Uint8Array.from([0, 0x11]));
  });
});
