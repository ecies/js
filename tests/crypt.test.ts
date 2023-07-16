import { ECIES_CONFIG } from "../src/config";
import { decrypt, encrypt } from "../src/index";
import { PrivateKey, PublicKey } from "../src/keys";

const TEXT = "helloworld🌍";

function check(sk: PrivateKey, compressed: boolean = false) {
  if (compressed) {
    const encrypted = encrypt(sk.publicKey.compressed, Buffer.from(TEXT));
    expect(decrypt(sk.secret, encrypted).toString()).toBe(TEXT);
  } else {
    const encrypted = encrypt(sk.publicKey.uncompressed, Buffer.from(TEXT));
    expect(decrypt(sk.secret, encrypted).toString()).toBe(TEXT);
  }
}
function checkHex(sk: PrivateKey) {
  const encrypted = encrypt(sk.publicKey.toHex(), Buffer.from(TEXT));
  expect(decrypt(sk.secret, encrypted).toString()).toBe(TEXT);
}

describe("test encrypt and decrypt", () => {
  it("tests encrypt/decrypt buffer", () => {
    const prv1 = new PrivateKey();
    check(prv1);

    const prv2 = new PrivateKey();
    check(prv2, true);
  });

  it("tests encrypt/decrypt hex", () => {
    const prv1 = new PrivateKey();
    checkHex(prv1);

    const prv2 = new PrivateKey();
    checkHex(prv2);
  });

  it("tests known sk pk", () => {
    const sk = PrivateKey.fromHex(
      "5b5b1a0ff51e4350badd6f58d9e6fa6f57fbdbde6079d12901770dda3b803081"
    );
    const pk = PublicKey.fromHex(
      "048e41409f2e109f2d704f0afd15d1ab53935fd443729913a7e8536b4cef8cf5773d4db7bbd99e9ed64595e24a251c9836f35d4c9842132443c17f6d501b3410d2"
    );
    const enc = encrypt(pk.toHex(), Buffer.from(TEXT));
    expect(decrypt(sk.toHex(), enc).toString()).toBe(TEXT);
  });

  it("tests ephemeral key config", () => {
    ECIES_CONFIG.isEphemeralKeyCompressed = true;

    const prv1 = new PrivateKey();
    check(prv1);

    ECIES_CONFIG.isEphemeralKeyCompressed = false;
  });
});
