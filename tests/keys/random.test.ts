import { ECIES_CONFIG, PrivateKey, PublicKey } from "../../src/index";

describe("test random keys", () => {
  function testRandom() {
    const k1 = new PrivateKey();
    const k2 = new PrivateKey();
    expect(k1.multiply(k2.publicKey)).toStrictEqual(k2.multiply(k1.publicKey));

    const sk = new PrivateKey();
    const skFromHex = PrivateKey.fromHex(sk.toHex());
    const pkFromHex = PublicKey.fromHex(sk.publicKey.toHex(false));

    expect(pkFromHex).toStrictEqual(sk.publicKey);
    expect(skFromHex).toStrictEqual(sk);
  }

  it("tests secp256k1", () => {
    testRandom();
  });

  it("tests curve25519", () => {
    ECIES_CONFIG.ellipticCurve = "x25519";

    testRandom();

    ECIES_CONFIG.ellipticCurve = "ed25519";

    testRandom();

    ECIES_CONFIG.ellipticCurve = "secp256k1";
  });
});
