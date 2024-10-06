import { PrivateKey, decrypt, encrypt } from "eciesjs";

const sk = new PrivateKey()
const data = Buffer.from("hello world🌍")
const decrypted = decrypt(sk.secret, encrypt(sk.publicKey.toHex(), data))
console.log(Buffer.from(decrypted).toString())
