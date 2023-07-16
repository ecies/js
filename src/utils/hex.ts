export function remove0x(hex: string): string {
  if (hex.startsWith("0x") || hex.startsWith("0X")) {
    return hex.slice(2);
  }
  return hex;
}

export function decodeHex(hex: string): Buffer {
  return Buffer.from(remove0x(hex), "hex");
}
