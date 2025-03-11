import { Buffer } from "node:buffer";
import { ECIES_CONFIG, PrivateKey, decrypt, encrypt } from "eciesjs";

// because deno does not support indirect conditional exports
// it falls to node:crypto's implementation
// despite that @ecies/ciphers exports @noble/ciphers implementation to deno
// see: https://github.com/denoland/deno/discussions/17964#discussioncomment-10917259
// since deno's `node:crypto` does not support xchacha20, you'll see error if next line is uncommented
// ECIES_CONFIG.symmetricAlgorithm = "xchacha20";

const sk = new PrivateKey();
const data = Buffer.from("hello world🌍");
const decrypted = decrypt(sk.secret, encrypt(sk.publicKey.toBytes(), data));
console.log(Buffer.from(decrypted).toString());
