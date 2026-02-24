export const IS_BUFFER_SUPPORTED = typeof globalThis.Buffer !== "undefined";

export type Bytes =
  | Uint8Array
  | (typeof globalThis.Buffer extends "undefined" ? never : globalThis.Buffer);
