/**
 * HChaCha20 implementation for XChaCha20.
 * Copied from @noble/ciphers/chacha (MIT License, Copyright Paul Miller).
 */

const rotl = (a: number, b: number): number => (a << b) | (a >>> (32 - b));

/**
 * HChaCha20 function - derives a subkey from a 256-bit key and 128-bit nonce.
 * Used internally for XChaCha20-Poly1305.
 */
export const _hchacha20 = (
  s: Uint32Array,
  k: Uint32Array,
  i: Uint32Array,
  o32: Uint32Array
): void => {
  // Initialize state from constants, key, and input
  let x00 = s[0]!;
  let x01 = s[1]!;
  let x02 = s[2]!;
  let x03 = s[3]!;
  let x04 = k[0]!;
  let x05 = k[1]!;
  let x06 = k[2]!;
  let x07 = k[3]!;
  let x08 = k[4]!;
  let x09 = k[5]!;
  let x10 = k[6]!;
  let x11 = k[7]!;
  let x12 = i[0]!;
  let x13 = i[1]!;
  let x14 = i[2]!;
  let x15 = i[3]!;

  // 20 rounds (10 double-rounds)
  for (let r = 0; r < 20; r += 2) {
    // Column round
    x00 = (x00 + x04) | 0;
    x12 = rotl(x12 ^ x00, 16);
    x08 = (x08 + x12) | 0;
    x04 = rotl(x04 ^ x08, 12);
    x00 = (x00 + x04) | 0;
    x12 = rotl(x12 ^ x00, 8);
    x08 = (x08 + x12) | 0;
    x04 = rotl(x04 ^ x08, 7);

    x01 = (x01 + x05) | 0;
    x13 = rotl(x13 ^ x01, 16);
    x09 = (x09 + x13) | 0;
    x05 = rotl(x05 ^ x09, 12);
    x01 = (x01 + x05) | 0;
    x13 = rotl(x13 ^ x01, 8);
    x09 = (x09 + x13) | 0;
    x05 = rotl(x05 ^ x09, 7);

    x02 = (x02 + x06) | 0;
    x14 = rotl(x14 ^ x02, 16);
    x10 = (x10 + x14) | 0;
    x06 = rotl(x06 ^ x10, 12);
    x02 = (x02 + x06) | 0;
    x14 = rotl(x14 ^ x02, 8);
    x10 = (x10 + x14) | 0;
    x06 = rotl(x06 ^ x10, 7);

    x03 = (x03 + x07) | 0;
    x15 = rotl(x15 ^ x03, 16);
    x11 = (x11 + x15) | 0;
    x07 = rotl(x07 ^ x11, 12);
    x03 = (x03 + x07) | 0;
    x15 = rotl(x15 ^ x03, 8);
    x11 = (x11 + x15) | 0;
    x07 = rotl(x07 ^ x11, 7);

    // Diagonal round
    x00 = (x00 + x05) | 0;
    x15 = rotl(x15 ^ x00, 16);
    x10 = (x10 + x15) | 0;
    x05 = rotl(x05 ^ x10, 12);
    x00 = (x00 + x05) | 0;
    x15 = rotl(x15 ^ x00, 8);
    x10 = (x10 + x15) | 0;
    x05 = rotl(x05 ^ x10, 7);

    x01 = (x01 + x06) | 0;
    x12 = rotl(x12 ^ x01, 16);
    x11 = (x11 + x12) | 0;
    x06 = rotl(x06 ^ x11, 12);
    x01 = (x01 + x06) | 0;
    x12 = rotl(x12 ^ x01, 8);
    x11 = (x11 + x12) | 0;
    x06 = rotl(x06 ^ x11, 7);

    x02 = (x02 + x07) | 0;
    x13 = rotl(x13 ^ x02, 16);
    x08 = (x08 + x13) | 0;
    x07 = rotl(x07 ^ x08, 12);
    x02 = (x02 + x07) | 0;
    x13 = rotl(x13 ^ x02, 8);
    x08 = (x08 + x13) | 0;
    x07 = rotl(x07 ^ x08, 7);

    x03 = (x03 + x04) | 0;
    x14 = rotl(x14 ^ x03, 16);
    x09 = (x09 + x14) | 0;
    x04 = rotl(x04 ^ x09, 12);
    x03 = (x03 + x04) | 0;
    x14 = rotl(x14 ^ x03, 8);
    x09 = (x09 + x14) | 0;
    x04 = rotl(x04 ^ x09, 7);
  }

  // Output first and last rows of the state matrix
  o32[0] = x00;
  o32[1] = x01;
  o32[2] = x02;
  o32[3] = x03;
  o32[4] = x12;
  o32[5] = x13;
  o32[6] = x14;
  o32[7] = x15;
};

/** Convert Uint8Array to Uint32Array (little-endian) */
export const u32 = (arr: Uint8Array): Uint32Array =>
  new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));

/** Convert Uint32Array to Uint8Array */
export const u8 = (arr: Uint32Array): Uint8Array =>
  new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
