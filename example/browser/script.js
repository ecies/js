import { bytesToHex } from "@noble/ciphers/utils";
import { ECIES_CONFIG, PrivateKey, decrypt, encrypt } from "eciesjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const els = {
  curve: document.querySelector("#curve"),
  algo: document.querySelector("#algo"),
  regenerate: document.querySelector("#regenerate"),
  publicKey: document.querySelector("#public-key"),
  secretKey: document.querySelector("#secret-key"),
  plaintext: document.querySelector("#plaintext"),
  encryptBtn: document.querySelector("#encrypt-btn"),
  ciphertext: document.querySelector("#ciphertext"),
  decryptBtn: document.querySelector("#decrypt-btn"),
  decrypted: document.querySelector("#decrypted"),
  themeToggle: document.querySelector("#theme-toggle"),
  themeLabel: document.querySelector("[data-theme-label]"),
};

const state = {
  sk: null,
  ciphertext: null,
};

const truncateMiddle = (hex, head = 28, tail = 16) =>
  hex.length > head + tail + 1 ? `${hex.slice(0, head)} … ${hex.slice(-tail)}` : hex;

/* Theme ─────────────────────────────────────── */
function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("eciesjs-theme", theme);
  els.themeLabel.textContent = theme === "dark" ? "Dark" : "Light";
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  setTheme(next);
}

/* Crypto ────────────────────────────────────── */
function applyConfig() {
  ECIES_CONFIG.ellipticCurve = els.curve.value;
  ECIES_CONFIG.symmetricAlgorithm = els.algo.value;
}

function regenerateKeys() {
  state.sk = new PrivateKey();
  els.publicKey.textContent = truncateMiddle(state.sk.publicKey.toHex());
  els.secretKey.textContent = truncateMiddle(bytesToHex(state.sk.secret));
  resetCiphertext();
}

function resetCiphertext() {
  state.ciphertext = null;
  els.ciphertext.textContent = "—";
  els.decrypted.textContent = "—";
  els.decryptBtn.disabled = true;
}

function handleEncrypt() {
  const text = els.plaintext.value;
  if (!text) {
    els.ciphertext.textContent = "(nothing to encrypt)";
    return;
  }
  try {
    state.ciphertext = encrypt(state.sk.publicKey.toHex(), encoder.encode(text));
    els.ciphertext.textContent = bytesToHex(state.ciphertext);
    els.decrypted.textContent = "—";
    els.decryptBtn.disabled = false;
  } catch (err) {
    els.ciphertext.textContent = `error: ${err.message}`;
  }
}

function handleDecrypt() {
  if (!state.ciphertext) return;
  try {
    const plain = decrypt(state.sk.secret, state.ciphertext);
    els.decrypted.textContent = decoder.decode(plain);
  } catch (err) {
    els.decrypted.textContent = `error: ${err.message}`;
  }
}

function handleConfigChange() {
  applyConfig();
  regenerateKeys();
}

/* Wire up ───────────────────────────────────── */
els.curve.addEventListener("change", handleConfigChange);
els.algo.addEventListener("change", handleConfigChange);
els.regenerate.addEventListener("click", regenerateKeys);
els.encryptBtn.addEventListener("click", handleEncrypt);
els.decryptBtn.addEventListener("click", handleDecrypt);
els.plaintext.addEventListener("input", resetCiphertext);
els.themeToggle.addEventListener("click", toggleTheme);

setTheme(document.documentElement.dataset.theme || "dark");
applyConfig();
regenerateKeys();
