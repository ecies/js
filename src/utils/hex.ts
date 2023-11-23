import { hexToBytes } from "@noble/ciphers/utils";

export const remove0x = (hex: string): string =>
  hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;

export const decodeHex = (hex: string): Uint8Array => hexToBytes(remove0x(hex));
