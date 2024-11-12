import { ECIES_CONFIG, PrivateKey, decrypt, encrypt } from "eciesjs";
import { Buffer } from "node:buffer";

globalThis.Buffer = Buffer;

// because deno does not support indirect conditional exports
// it falls to node:crypto's implementation
// despite that @ecies/ciphers exports @noble/ciphers implementation to deno
// see: https://github.com/denoland/deno/discussions/17964#discussioncomment-10917259
// deno's node:crypto does not support 16 bytes iv
// so aes-256-gcm (16 bytes iv) does not work
ECIES_CONFIG.symmetricNonceLength = 12;
// ECIES_CONFIG.symmetricAlgorithm = "xchacha20";

const sk = new PrivateKey();
const data = Buffer.from("hello world🌍");
const decrypted = decrypt(sk.secret, encrypt(sk.publicKey.toBytes(), data));
console.log(Buffer.from(decrypted).toString());
