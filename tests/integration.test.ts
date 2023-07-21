import axios from "axios";
import { stringify } from "querystring";

import { decrypt, encrypt } from "../src/index";
import { PrivateKey } from "../src/keys";
import { decodeHex } from "../src/utils";

const PYTHON_BACKEND = "https://eciespydemo-1-d5397785.deta.app/";

const TEXT = "helloworld🌍";

describe("test encrypt and decrypt", () => {
  const prv = new PrivateKey();

  it("tests encryption against python version", async () => {
    const res = await axios.post(
      PYTHON_BACKEND,
      stringify({
        data: TEXT,
        pub: prv.publicKey.toHex(),
      })
    );
    const encryptedKnown = decodeHex(res.data);
    const decrypted = decrypt(prv.toHex(), encryptedKnown);

    expect(decrypted.toString()).toEqual(TEXT);
  });

  it("tests decryption against python version", async () => {
    const encrypted = encrypt(prv.publicKey.toHex(), Buffer.from(TEXT));
    const res = await axios.post(
      PYTHON_BACKEND,
      stringify({
        data: encrypted.toString("hex"),
        prv: prv.toHex(),
      })
    );
    expect(TEXT).toEqual(res.data);
  });
});
