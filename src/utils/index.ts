export * from "./elliptic.js";
export * from "./hash.js";
export * from "./hex.js";
export * from "./symmetric.js";

// Import all exports to create a default export
import * as elliptic from "./elliptic.js";
import * as hash from "./hash.js";
import * as hex from "./hex.js";
import * as symmetric from "./symmetric.js";

// Default export for backward compatibility with default imports
const utils = {
  ...elliptic,
  ...hash,
  ...hex,
  ...symmetric,
};

export default utils;
