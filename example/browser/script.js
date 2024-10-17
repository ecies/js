import { bytesToHex } from "@noble/ciphers/utils";
import { Buffer } from "buffer";
import { PrivateKey, decrypt, encrypt } from "eciesjs";

import "./style.css";

globalThis.Buffer = Buffer;

const sk = new PrivateKey();
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function setup(encryptedElement, textElement, decryptedElement) {
  const text = "hello eciesjs🔒";
  let encrypted;

  encryptedElement.innerHTML = `click me to encrypt`;
  textElement.innerHTML = text;
  decryptedElement.innerHTML = `click me to decrypt`;

  const _encrypt = () => {
    encrypted = encrypt(sk.publicKey.toHex(), encoder.encode(text));
    encryptedElement.innerHTML = `encrypted:`;
    textElement.innerHTML = `${bytesToHex(encrypted)}`;
    decryptedElement.innerHTML = `click me to decrypt`;
  };
  const _decrypt = () => {
    encryptedElement.innerHTML = `click me to encrypt`;
    if (encrypted) {
      textElement.innerHTML = `${decoder.decode(decrypt(sk.secret, encrypted))}`;
      decryptedElement.innerHTML = `decrypted:`;
      encrypted = undefined;
    } else {
      textElement.innerHTML = "click encrypt button first";
    }
  };
  encryptedElement.addEventListener("click", () => _encrypt());
  decryptedElement.addEventListener("click", () => _decrypt());
}

document.querySelector("#app").innerHTML = `
  <div>
    <h1>Hello eciesjs!</h1>
    <div class="card">
      <button id="encrypted" type="button"></button>
      <button id="decrypted" type="button"></button>
    </div>
    <p id="text"></p>
  </div>
`;

setup(
  document.querySelector("#encrypted"),
  document.querySelector("#text"),
  document.querySelector("#decrypted")
);
