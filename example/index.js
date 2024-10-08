import { ECIES_CONFIG, PrivateKey, decrypt, encrypt } from "eciesjs";
import { Buffer } from "node:buffer";

globalThis.Buffer = Buffer;
ECIES_CONFIG.symmetricNonceLength = 12

const sk = new PrivateKey()
const data = Buffer.from("hello world🌍")
const decrypted = decrypt(sk.secret, encrypt(sk.publicKey.toHex(), data))
console.log(Buffer.from(decrypted).toString())
