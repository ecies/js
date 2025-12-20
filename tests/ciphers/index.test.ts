import { randomBytes } from "@noble/ciphers/utils.js";
import { describe, expect, it } from "vitest";

import {
  aes256cbc,
  aes256gcm,
  chacha20,
  isUsingNativeChaCha,
  isUsingNativeCrypto,
  xchacha20,
} from "../../src/ciphers/index.js";

const TEXT = "hello world🌍!";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

describe("test cipher index exports", () => {
  it("tests aes256gcm encrypt/decrypt", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(16);
    const aad = randomBytes(8);
    const data = encoder.encode(TEXT);

    const cipher = aes256gcm(key, nonce, aad);
    const encrypted = cipher.encrypt(data);
    const decrypted = cipher.decrypt(encrypted);

    expect(decoder.decode(decrypted)).toBe(TEXT);
  });

  it("tests aes256gcm without AAD", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const data = encoder.encode(TEXT);

    const cipher = aes256gcm(key, nonce);
    const encrypted = cipher.encrypt(data);
    const decrypted = cipher.decrypt(encrypted);

    expect(decoder.decode(decrypted)).toBe(TEXT);
  });

  it("tests aes256cbc encrypt/decrypt", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(16);
    const data = encoder.encode(TEXT);

    const cipher = aes256cbc(key, nonce);
    const encrypted = cipher.encrypt(data);
    const decrypted = cipher.decrypt(encrypted);

    expect(decoder.decode(decrypted)).toBe(TEXT);
  });

  it("tests xchacha20 encrypt/decrypt", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const aad = randomBytes(8);
    const data = encoder.encode(TEXT);

    const cipher = xchacha20(key, nonce, aad);
    const encrypted = cipher.encrypt(data);
    const decrypted = cipher.decrypt(encrypted);

    expect(decoder.decode(decrypted)).toBe(TEXT);
  });

  it("tests xchacha20 without AAD", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const data = encoder.encode(TEXT);

    const cipher = xchacha20(key, nonce);
    const encrypted = cipher.encrypt(data);
    const decrypted = cipher.decrypt(encrypted);

    expect(decoder.decode(decrypted)).toBe(TEXT);
  });

  it("tests chacha20 encrypt/decrypt", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const aad = randomBytes(8);
    const data = encoder.encode(TEXT);

    const cipher = chacha20(key, nonce, aad);
    const encrypted = cipher.encrypt(data);
    const decrypted = cipher.decrypt(encrypted);

    expect(decoder.decode(decrypted)).toBe(TEXT);
  });

  it("tests chacha20 without AAD", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const data = encoder.encode(TEXT);

    const cipher = chacha20(key, nonce);
    const encrypted = cipher.encrypt(data);
    const decrypted = cipher.decrypt(encrypted);

    expect(decoder.decode(decrypted)).toBe(TEXT);
  });

  it("tests isUsingNativeCrypto returns boolean", () => {
    const result = isUsingNativeCrypto();
    expect(typeof result).toBe("boolean");
  });

  it("tests isUsingNativeChaCha returns boolean", () => {
    const result = isUsingNativeChaCha();
    expect(typeof result).toBe("boolean");
  });
});
