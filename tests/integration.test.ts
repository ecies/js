import { fetch, ProxyAgent, RequestInit } from 'undici';

import { decrypt, encrypt, PrivateKey, utils } from "../src/index";

const decodeHex = utils.decodeHex;

const PYTHON_BACKEND = "https://demo.ecies.org/";
const TEXT = "helloworld🌍";

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
    const encrypted = encrypt(sk.publicKey.toHex(), Buffer.from(TEXT));
    const res = await eciesApi(PYTHON_BACKEND, {
      data: encrypted.toString("hex"),
      prv: sk.toHex(),
    });
    expect(TEXT).toEqual(await res.text());
  });
});

async function eciesApi(
  url: string,
  body: { data: string; pub?: string; prv?: string }
) {
  const config: RequestInit = {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
  };
  if (process.env.http_proxy !== undefined) {
    config.dispatcher = new ProxyAgent(`${process.env.http_proxy}`);
  }

  return await fetch(url, {
    ...config,
    body: new URLSearchParams(body),
  });
}
