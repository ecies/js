import { describe, expect, it } from "vitest";

import { bytesToHex } from "@noble/ciphers/utils";
import { fetch, ProxyAgent, RequestInit } from "undici";

import { decrypt, encrypt, PrivateKey } from "../src";
import { decodeHex } from "../src/utils";

const PYTHON_BACKEND = "https://demo.ecies.org/";
const TEXT = "helloworld🌍";
const encoder = new TextEncoder();

describe("test encrypt and decrypt against python version", () => {
  it("tests encrypt", async () => {
    const sk = new PrivateKey();
    const res = await eciesApi(PYTHON_BACKEND, {
      data: TEXT,
      pub: sk.publicKey.toHex(),
    });
    const decrypted = decrypt(sk.toHex(), decodeHex(await res.text()));
    expect(decrypted.toString()).toEqual(TEXT);
  });

  it("tests decrypt", async () => {
    const sk = new PrivateKey();
    const encrypted = encrypt(sk.publicKey.toHex(), encoder.encode(TEXT));
    const res = await eciesApi(PYTHON_BACKEND, {
      data: bytesToHex(encrypted),
      prv: sk.toHex(),
    });
    expect(TEXT).toEqual(await res.text());
  });
});

async function eciesApi(url: string, body: { data: string; pub?: string; prv?: string }) {
  const config: RequestInit = {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
  };
  const proxy = process.env.https_proxy || process.env.http_proxy;
  if (proxy) {
    config.dispatcher = new ProxyAgent(`${proxy}`);
  }

  return await fetch(url, {
    ...config,
    body: new URLSearchParams(body),
  });
}
