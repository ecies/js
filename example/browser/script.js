import { Buffer } from "buffer";
import { bytesToHex } from "@noble/ciphers/utils";
import { ECIES_CONFIG, PrivateKey, decrypt, encrypt } from "eciesjs";

import "./style.css";

globalThis.Buffer = Buffer; // polyfill manually

ECIES_CONFIG.ellipticCurve = "x25519";
ECIES_CONFIG.symmetricAlgorithm = "xchacha20";

const sk = new PrivateKey();
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function setup(inputElement, textElement, encryptedElement, decryptedElement) {
  let encrypted;
  let text = inputElement.value;
  textElement.innerHTML = text;
  encryptedElement.innerHTML = "click me to encrypt";
  decryptedElement.innerHTML = "click me to decrypt";

  const _encrypt = () => {
    encrypted = encrypt(sk.publicKey.toHex(), encoder.encode(text));
    encryptedElement.innerHTML = "encrypted:";
    textElement.innerHTML = `<code>${bytesToHex(encrypted)}</code>`;
    decryptedElement.innerHTML = "click me to decrypt";
  };
  const _decrypt = () => {
    encryptedElement.innerHTML = "click me to encrypt";
    if (encrypted) {
      const decrypted = decoder.decode(decrypt(sk.secret, encrypted));
      textElement.innerHTML = `${decrypted}`;
      decryptedElement.innerHTML = "decrypted:";
      encrypted = undefined;
    } else {
      textElement.innerHTML = "click encrypt button first";
    }
  };
  const _onTextInput = (e) => {
    const target = e.target;
    if (target) {
      encrypted = undefined;
      const value = target.value;
      text = value;
      textElement.innerHTML = value;
      encryptedElement.innerHTML = "click me to encrypt";
      decryptedElement.innerHTML = "click me to decrypt";
    }
  };
  encryptedElement.addEventListener("click", () => _encrypt());
  decryptedElement.addEventListener("click", () => _decrypt());
  inputElement.addEventListener("input", _onTextInput);
}

document.querySelector("#app").innerHTML = `
  <div>
    <h1>Hello eciesjs!</h1>
    <div class="card">
      <button id="encrypted" type="button"></button>
      <button id="decrypted" type="button"></button>
    </div>
    <input id="text-input" type="text" value="hello eciesjs🔒" />
    <p id="text"></p>
  </div>
`;

setup(
  document.querySelector("#text-input"),
  document.querySelector("#text"),
  document.querySelector("#encrypted"),
  document.querySelector("#decrypted")
);
