import { Buffer } from "node:buffer";
import { ECIES_CONFIG, PrivateKey, decrypt, encrypt } from "eciesjs";

// because deno does not support indirect conditional exports by default
// it falls to node:crypto's implementation
// despite that @ecies/ciphers exports @noble/ciphers implementation to deno
// see: https://github.com/denoland/deno/issues/23757#issuecomment-3010699763
// you need to run with `--conditions deno` (>=2.4.0) or
// `--unstable-node-conditions` (>=2.3.6,<2.4.0) if next line is uncommented
// ECIES_CONFIG.symmetricAlgorithm = "xchacha20";

const sk = new PrivateKey();
const data = Buffer.from("hello world🌍");
const decrypted = decrypt(sk.secret, encrypt(sk.publicKey.toBytes(), data));
console.log(Buffer.from(decrypted).toString());
