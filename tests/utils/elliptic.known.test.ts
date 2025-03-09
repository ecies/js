import { describe, expect, it } from "vitest";

import { hexToBytes } from "@noble/hashes/utils";

import type { EllipticCurve } from "../../src/config";
import { decodeHex, getSharedPoint, hexToPublicKey } from "../../src/utils";

describe("test known elliptic", () => {
  function testGetSharedPoint(
    sk: string,
    pk: string,
    shared: string,
    compressed: boolean = true,
    curve?: EllipticCurve
  ) {
    expect(
      getSharedPoint(decodeHex(sk), hexToPublicKey(pk, curve), compressed, curve)
    ).toStrictEqual(decodeHex(shared));
  }

  const pkOfTwo =
    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a";

  it("tests hexToPublicKey: secp256k1", () => {
    expect(hexToPublicKey(pkOfTwo, "secp256k1")).toStrictEqual(
      hexToBytes("04" + pkOfTwo)
    );
  });

  it("tests getSharedPoint: secp256k1", () => {
    testGetSharedPoint(
      "0000000000000000000000000000000000000000000000000000000000000003",
      pkOfTwo,
      "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556", //6's pk
      true,
      "secp256k1"
    );
  });

  it("tests getSharedPoint: x25519", () => {
    // https://datatracker.ietf.org/doc/html/rfc7748.html#section-6.1
    testGetSharedPoint(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
      true,
      "x25519"
    );
  });

  it("tests getSharedPoint: ed25519", () => {
    // scalar of sk: 3140620980319341722849076354004524857726602937622481303882784251885505225391
    // shared point:
    //   (10766034509508892393929108371050440292889843231095811528019173932139015419574,
    //    57672573619093321322151945555557301978191423137769245365888971894976817047673)

    testGetSharedPoint(
      "0000000000000000000000000000000000000000000000000000000000000000", // sk
      "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29", // peer pk
      "79a82a4ed2cbf9cab6afbf353df0a225b58642c0c7b3760a99856bf01785817f",
      false,
      "ed25519"
    );

    testGetSharedPoint(
      "0000000000000000000000000000000000000000000000000000000000000001", // peer sk
      "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
      "79a82a4ed2cbf9cab6afbf353df0a225b58642c0c7b3760a99856bf01785817f",
      true,
      "ed25519"
    );
  });
});
