import { ed25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

import { decrypt, encrypt, PrivateKey } from "../../src";
import { Config, type EllipticCurve } from "../../src/config";

// records each HKDF input (ephemeral key || shared point) and output (the symmetric key)
vi.mock("@noble/hashes/hkdf", async (importOriginal) => {
  const mod = await importOriginal<typeof import("@noble/hashes/hkdf")>();
  return { ...mod, hkdf: vi.fn(mod.hkdf) };
});

const multiply = vi.spyOn(PrivateKey.prototype, "multiply"); // returns the shared point
const encapsulate = vi.spyOn(PrivateKey.prototype, "encapsulate"); // on the ephemeral key
// on ed25519, returns the secret key's hash: its head is the secret scalar's bytes
const getExtendedPublicKey = vi.spyOn(ed25519.utils, "getExtendedPublicKey");

afterAll(() => {
  multiply.mockRestore();
  encapsulate.mockRestore();
  getExtendedPublicKey.mockRestore();
});

beforeEach(() => {
  vi.clearAllMocks();
});

const isWiped = (bytes: Uint8Array) => bytes.every((b) => b === 0);

// After encrypt or decrypt returns, the shared point, the HKDF input, the derived key, the
// ephemeral secret key and, on ed25519, the hashed secret keys each open the payload together
// with its ephemeral public key, so each must be wiped (#925)
describe.each<EllipticCurve>(["secp256k1", "x25519", "ed25519"])(
  "encrypt and decrypt wipe what opens the payload on %s (#925)",
  (curve) => {
    const config = new Config();
    config.ellipticCurve = curve;
    const message = new TextEncoder().encode("hello world🌍");

    // checks the one key derivation that encrypt or decrypt ran, and every hashed secret key
    // that eciesjs got from ed25519.utils
    const expectWiped = () => {
      const hkdfMock = vi.mocked(hkdf).mock;
      expect(hkdfMock.calls).toHaveLength(1);
      expect(isWiped(hkdfMock.calls[0][1] as Uint8Array)).toBe(true); // the HKDF input
      expect(isWiped(hkdfMock.results[0].value)).toBe(true); // the derived key
      expect(multiply.mock.results).toHaveLength(1);
      expect(isWiped(multiply.mock.results[0].value)).toBe(true); // the shared point

      const extendedKeys = getExtendedPublicKey.mock.results;
      expect(extendedKeys.length > 0).toBe(curve === "ed25519");
      for (const { value } of extendedKeys) {
        expect(isWiped(value.head)).toBe(true);
        expect(isWiped(value.prefix)).toBe(true);
      }
    };

    it("encrypt wipes the shared point, HKDF input, derived key and ephemeral secret", () => {
      const receiver = new PrivateKey(undefined, curve);
      const receiverPK = receiver.publicKey.toBytes();
      const receiverPKBefore = Uint8Array.from(receiverPK);

      const payload = encrypt(receiverPK, message, config);

      expectWiped();
      const ephemeralSK = encapsulate.mock.contexts[0] as PrivateKey;
      expect(isWiped(ephemeralSK.secret)).toBe(true);
      expect(receiverPK).toStrictEqual(receiverPKBefore);
      expect(decrypt(receiver.secret, payload, config)).toStrictEqual(message);
    });

    it("decrypt wipes what it derived and keeps the caller's key and payload", () => {
      const receiver = new PrivateKey(undefined, curve);
      const payload = encrypt(receiver.publicKey.toBytes(), message, config);
      const secretBefore = Uint8Array.from(receiver.secret);
      const payloadBefore = Uint8Array.from(payload);
      vi.clearAllMocks();

      expect(decrypt(receiver.secret, payload, config)).toStrictEqual(message);

      expectWiped();
      expect(receiver.secret).toStrictEqual(secretBefore);
      expect(payload).toStrictEqual(payloadBefore);
    });

    it("decrypt wipes what it derived even if the tag check fails", () => {
      const receiver = new PrivateKey(undefined, curve);
      const payload = encrypt(receiver.publicKey.toBytes(), message, config);
      payload[payload.length - 1] ^= 1;
      vi.clearAllMocks();

      expect(() => decrypt(receiver.secret, payload, config)).toThrow();

      expectWiped();
    });
  }
);

// On ed25519, new PrivateKey derives its public key from the hashed secret key: encrypt builds
// one for the ephemeral key and decrypt one for the receiver's. expectWiped sees only the
// hashes that eciesjs gets from ed25519.utils, so this pins that new PrivateKey gets its hash
// there too, and that the public key is still the one noble gives (#925)
describe("new PrivateKey wipes its hashed secret key on ed25519 (#925)", () => {
  it("wipes head and prefix, and gives noble's public key", () => {
    const sk = new PrivateKey(undefined, "ed25519");

    expect(getExtendedPublicKey).toHaveBeenCalledTimes(1);
    const { head, prefix } = getExtendedPublicKey.mock.results[0].value;
    expect(isWiped(head)).toBe(true);
    expect(isWiped(prefix)).toBe(true);
    expect(sk.publicKey.toBytes()).toStrictEqual(ed25519.getPublicKey(sk.secret));
  });
});
