/**
 * Cipher implementations with automatic platform detection.
 *
 * Uses Node.js native crypto when available for better performance,
 * falls back to @noble/ciphers for browsers and environments without node:crypto.
 */
import { createRequire } from "node:module";
import type { Cipher } from "@noble/ciphers/utils.js";

type CipherFactory = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher;

// Runtime detection state
let _initialized = false;
let _useNodeCrypto = false;
let _nodeAes: typeof import("./aes.node.js") | null = null;
let _nodeChacha: typeof import("./chacha.node.js") | null = null;

// Runtime environment detection
const IS_BROWSER =
  typeof window !== "undefined" ||
  (typeof self !== "undefined" && typeof self.document !== "undefined");
const IS_DENO = "Deno" in globalThis;
const IS_BUN = "Bun" in globalThis;

// Noble ciphers (always available as fallback)
import { cbc, gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305, xchacha20poly1305 } from "@noble/ciphers/chacha.js";

/**
 * Synchronously try to load native crypto modules.
 */
function tryInitSync(): void {
  if (_initialized) return;
  _initialized = true;

  if (IS_BROWSER) return;

  try {
    // Use createRequire for ESM compatibility
    const require = createRequire(import.meta.url);
    const cryptoModule = require("node:crypto");

    /* v8 ignore next 8 -- @preserve: native crypto loading only works in built package */
    if (cryptoModule && typeof cryptoModule.createCipheriv === "function") {
      // Load the node-specific cipher implementations
      _nodeAes = require("./aes.node.js");
      if (!IS_DENO && !IS_BUN) {
        _nodeChacha = require("./chacha.node.js");
      }
      _useNodeCrypto = true;
    }
  } catch {
    // node:crypto not available or require not available, fall back to noble ciphers
  }
}

// Initialize on module load
tryInitSync();

/**
 * AES-256-GCM cipher factory.
 * Uses node:crypto on Node.js, @noble/ciphers elsewhere.
 */
export const aes256gcm: CipherFactory = (key, nonce, AAD) => {
  /* v8 ignore next 3 -- @preserve: native path only in built package */
  if (_useNodeCrypto && _nodeAes) {
    return _nodeAes.aes256gcm(key, nonce, AAD);
  }
  return gcm(key, nonce, AAD);
};

/**
 * AES-256-CBC cipher factory.
 * Uses node:crypto on Node.js, @noble/ciphers elsewhere.
 */
export const aes256cbc: CipherFactory = (key, nonce, _AAD) => {
  /* v8 ignore next 3 -- @preserve: native path only in built package */
  if (_useNodeCrypto && _nodeAes) {
    return _nodeAes.aes256cbc(key, nonce);
  }
  return cbc(key, nonce);
};

/**
 * XChaCha20-Poly1305 cipher factory.
 * Uses node:crypto on Node.js (with HChaCha20), @noble/ciphers elsewhere.
 */
export const xchacha20: CipherFactory = (key, nonce, AAD) => {
  /* v8 ignore next 3 -- @preserve: native path only in built package */
  if (_useNodeCrypto && _nodeChacha) {
    return _nodeChacha.xchacha20(key, nonce, AAD);
  }
  return xchacha20poly1305(key, nonce, AAD);
};

/**
 * ChaCha20-Poly1305 cipher factory.
 * Uses node:crypto on Node.js, @noble/ciphers elsewhere.
 */
export const chacha20: CipherFactory = (key, nonce, AAD) => {
  /* v8 ignore next 3 -- @preserve: native path only in built package */
  if (_useNodeCrypto && _nodeChacha) {
    return _nodeChacha.chacha20(key, nonce, AAD);
  }
  return chacha20poly1305(key, nonce, AAD);
};

/**
 * Returns true if native crypto is being used.
 * Useful for debugging and testing.
 */
export const isUsingNativeCrypto = (): boolean => _useNodeCrypto;

/**
 * Returns true if native ChaCha is being used.
 * ChaCha native is only available on Node.js (not Deno/Bun).
 */
export const isUsingNativeChaCha = (): boolean => _useNodeCrypto && _nodeChacha !== null;
