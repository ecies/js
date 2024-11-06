import { describe, expect, it } from "vitest";

import { bytesToHex, bytesToUtf8 } from "@noble/ciphers/utils";
import { ProxyAgent, request } from "undici";

import { decrypt, encrypt, PrivateKey } from "../src";
import { decodeHex } from "../src/utils";

const PYTHON_BACKEND = "https://demo.ecies.org/";
const TEXT = "hello world🌍";
const encoder = new TextEncoder();

describe("test encrypt and decrypt against python version", () => {
  it("tests encrypt", async () => {
    const sk = new PrivateKey();
    const res = await eciesApi(PYTHON_BACKEND, {
      data: TEXT,
      pub: sk.publicKey.toHex(),
    });
    const decrypted = bytesToUtf8(decrypt(sk.toHex(), decodeHex(await res.text())));
    expect(decrypted).toStrictEqual(TEXT);
  });

  it("tests decrypt", async () => {
    const sk = new PrivateKey();
    const encrypted = encrypt(sk.publicKey.toHex(), encoder.encode(TEXT));
    const res = await eciesApi(PYTHON_BACKEND, {
      data: bytesToHex(encrypted),
      prv: sk.toHex(),
    });
    expect(TEXT).toStrictEqual(await res.text());
  });
});

async function eciesApi(
  url: string,
  params: { data: string; pub?: string; prv?: string }
) {
  const proxy = process.env.https_proxy || process.env.http_proxy;

  const { body } = await request(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params).toString(),
    dispatcher: proxy !== undefined ? new ProxyAgent(proxy) : undefined,
  });
  return body;
}
