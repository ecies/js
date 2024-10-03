import { ECIES_CONFIG } from "../../src";
import {
  decodeHex,
  getSharedPoint,
  getValidSecret,
  isValidPrivateKey,
} from "../../src/utils/";

describe("test random elliptic", () => {
  it("generates valid secret", () => {
    const key = getValidSecret();
    expect(isValidPrivateKey(key)).toBe(true);
  });
});

describe("test known elliptic", () => {
  function testKnown(sk: string, pk: string, shared: string) {
    expect(getSharedPoint(decodeHex(sk), decodeHex(pk))).toStrictEqual(decodeHex(shared));
  }

  it("tests x25519", () => {
    ECIES_CONFIG.ellipticCurve = "x25519";

    // https://datatracker.ietf.org/doc/html/rfc7748.html#section-6.1
    testKnown(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    );

    ECIES_CONFIG.ellipticCurve = "secp256k1";
  });

  it("tests ed25519", () => {
    ECIES_CONFIG.ellipticCurve = "ed25519";

    // scalar of sk: 3140620980319341722849076354004524857726602937622481303882784251885505225391
    // shared point:
    //   (10766034509508892393929108371050440292889843231095811528019173932139015419574,
    //    57672573619093321322151945555557301978191423137769245365888971894976817047673)

    testKnown(
      "0000000000000000000000000000000000000000000000000000000000000000", // sk
      "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29", // peer pk
      "79a82a4ed2cbf9cab6afbf353df0a225b58642c0c7b3760a99856bf01785817f"
    );

    testKnown(
      "0000000000000000000000000000000000000000000000000000000000000001", // peer sk
      "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
      "79a82a4ed2cbf9cab6afbf353df0a225b58642c0c7b3760a99856bf01785817f"
    );

    ECIES_CONFIG.ellipticCurve = "secp256k1";
  });
});
