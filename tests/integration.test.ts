import { HttpsProxyAgent } from "https-proxy-agent";
import fetch, { RequestInit } from "node-fetch";
import { PrivateKey, decrypt, encrypt, utils } from "../src/index";

const decodeHex = utils.decodeHex;

const PYTHON_BACKEND = "https://eciespydemo-1-d5397785.deta.app/";
const TEXT = "helloworld🌍";

describe("test encrypt and decrypt", () => {
  it("tests encryption against python version", async () => {
    const prv = new PrivateKey();
    const res = await eciesApi(PYTHON_BACKEND, {
      data: TEXT,
      pub: prv.publicKey.toHex(),
    });
    const encryptedKnown = decodeHex(await res.text());
    const decrypted = decrypt(prv.toHex(), Buffer.from(encryptedKnown));

    expect(decrypted.toString()).toEqual(TEXT);
  });

  it("tests decryption against python version", async () => {
    const prv = new PrivateKey();
    const encrypted = encrypt(prv.publicKey.toHex(), Buffer.from(TEXT));
    const res = await eciesApi(PYTHON_BACKEND, {
      data: encrypted.toString("hex"),
      prv: prv.toHex(),
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
    config.agent = new HttpsProxyAgent(`${process.env.http_proxy}`);
  }

  return await fetch(url, {
    ...config,
    body: new URLSearchParams(body),
  });
}
