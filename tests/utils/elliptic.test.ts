import { utils } from "../../src/index";
import { isValidPrivateKey } from "../../src/utils";

const { getValidSecret } = utils;

describe("test elliptic utils", () => {
  it("should generate valid secret", () => {
    const key = getValidSecret();
    expect(isValidPrivateKey(key)).toBe(true);
  });
});
