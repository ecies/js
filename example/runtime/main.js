import { ECIES_CONFIG, PrivateKey, decrypt, encrypt } from "eciesjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const run = (curve, algorithm, message) => {
  ECIES_CONFIG.ellipticCurve = curve;
  // because deno does not support indirect conditional exports by default
  // it falls to node:crypto's implementation
  // despite that @ecies/ciphers exports @noble/ciphers implementation to deno
  // see: https://github.com/denoland/deno/issues/23757#issuecomment-3010699763
  // you need to run with `--conditions deno` (>=2.4.0) or
  // `--unstable-node-conditions` (>=2.3.6,<2.4.0) for xchacha20 support
  ECIES_CONFIG.symmetricAlgorithm = algorithm;

  const sk = new PrivateKey();
  const data = encoder.encode(message);
  const decrypted = decrypt(sk.secret, encrypt(sk.publicKey.toBytes(), data));
  console.log(`${curve} ${algorithm}: ` + decoder.decode(decrypted));
};

const msg = "hello world🌍";
run("secp256k1", "aes-256-gcm", msg);
run("secp256k1", "xchacha20", msg);
run("x25519", "aes-256-gcm", msg);
run("x25519", "xchacha20", msg);
run("ed25519", "aes-256-gcm", msg);
run("ed25519", "xchacha20", msg);
