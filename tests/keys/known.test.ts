import { describe, expect, it } from "vitest";

import { PrivateKey, PublicKey } from "../../src";
import { decodeHex } from "../../src/utils";

describe("test known keys", () => {
  function checkEncapsulate(
    k1: PrivateKey,
    k2: PrivateKey,
    knownHex: string,
    compressed: boolean
  ) {
    const known = decodeHex(knownHex);
    expect(k1.encapsulate(k2.publicKey, compressed)).toStrictEqual(known);
    expect(k1.publicKey.decapsulate(k2, compressed)).toStrictEqual(known);
  }

  it("tests key compatibility", () => {
    const _sk = "95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d";
    const _pk = // eth format
      "98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140" +
      "a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b";
    const sk = PrivateKey.fromHex(_sk);
    const pk = PublicKey.fromHex(_pk);
    expect(pk).toStrictEqual(sk.publicKey);
    expect(pk.equals(sk.publicKey)).toBe(true);

    expect(pk.toHex(true)).toStrictEqual("03" + _pk.substring(0, 64));
    expect(pk.toHex(false)).toStrictEqual("04" + _pk);
  });

  it("tests encapsulate: secp256k1", () => {
    const two = Uint8Array.from(Array(31).fill(0).concat([2]));
    const three = Uint8Array.from(Array(31).fill(0).concat([3]));

    const k1 = new PrivateKey(two, "secp256k1");
    const k2 = new PrivateKey(three, "secp256k1");

    checkEncapsulate(
      k1,
      k2,
      "6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82",
      false
    );

    checkEncapsulate(
      k1,
      k2,
      "b192b226edb3f02da11ef9c6ce4afe1c7e40be304e05ae3b988f4834b1cb6c69",
      true
    );
  });

  it("tests encapsulate: x25519", () => {
    const two = Uint8Array.from(Array(31).fill(0).concat([2]));
    const three = Uint8Array.from(Array(31).fill(0).concat([3]));

    const k1 = new PrivateKey(two, "x25519");
    const k2 = new PrivateKey(three, "x25519");

    checkEncapsulate(
      k1,
      k2,
      "d8f3f4d3ed301a58dd1309c372cfd147ad881dc44f495948b3e47c4e07114d0c",
      false
    );

    checkEncapsulate(
      k1,
      k2,
      "d8f3f4d3ed301a58dd1309c372cfd147ad881dc44f495948b3e47c4e07114d0c",
      true
    );
  });

  it("tests encapsulate: ed25519", () => {
    const two = Uint8Array.from(Array(31).fill(0).concat([2]));
    const three = Uint8Array.from(Array(31).fill(0).concat([3]));

    const k1 = new PrivateKey(two, "ed25519");
    const k2 = new PrivateKey(three, "ed25519");

    checkEncapsulate(
      k1,
      k2,
      "0c39bd5bbeaa991f10dfb399c1d326a1280812a53ba143a5edae0a8d737c45ca",
      false
    );

    checkEncapsulate(
      k1,
      k2,
      "0c39bd5bbeaa991f10dfb399c1d326a1280812a53ba143a5edae0a8d737c45ca",
      true
    );
  });
});
