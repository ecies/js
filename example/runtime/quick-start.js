import { PrivateKey, decrypt, encrypt } from "eciesjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const sk = new PrivateKey();
const data = encoder.encode("hello world🌍");
const decrypted = decrypt(sk.secret, encrypt(sk.publicKey.toBytes(), data));
console.log(decoder.decode(decrypted));
