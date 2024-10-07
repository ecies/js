import { describe, expect, it } from "vitest";

import { decodeHex, deriveKey } from "../../src/utils";

describe("test known hash", () => {
  it("tests hkdf", () => {
    const knownKey = decodeHex(
      "0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
    );
    expect(knownKey).toStrictEqual(
      deriveKey(decodeHex("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
    );
  });
});
