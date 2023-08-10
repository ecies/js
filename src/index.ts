import { concatBytes } from "@noble/ciphers/utils";
import { ephemeralKeySize, isEphemeralKeyCompressed } from "./config";
import { PrivateKey, PublicKey } from "./keys";
import { aesDecrypt, aesEncrypt, decodeHex, getValidSecret, remove0x } from "./utils";

export function encrypt(receiverRawPK: string | Buffer, msg: Buffer): Buffer {
  const ephemeralKey = new PrivateKey();

  const receiverPK =
    receiverRawPK instanceof Uint8Array
      ? new PublicKey(receiverRawPK)
      : PublicKey.fromHex(receiverRawPK);

  const aesKey = ephemeralKey.encapsulate(receiverPK);
  const encrypted = aesEncrypt(aesKey, msg);

  let pk: Buffer;
  if (isEphemeralKeyCompressed()) {
    pk = ephemeralKey.publicKey.compressed;
  } else {
    pk = ephemeralKey.publicKey.uncompressed;
  }
  return Buffer.from(concatBytes(pk, encrypted));
}

export function decrypt(receiverRawSK: string | Buffer, msg: Buffer): Buffer {
  const receiverSK =
    receiverRawSK instanceof Uint8Array
      ? new PrivateKey(receiverRawSK)
      : PrivateKey.fromHex(receiverRawSK);

  const keySize = ephemeralKeySize();
  const senderPubkey = new PublicKey(msg.subarray(0, keySize));
  const encrypted = msg.subarray(keySize);
  const aesKey = senderPubkey.decapsulate(receiverSK);
  return Buffer.from(aesDecrypt(aesKey, encrypted));
}

export { ECIES_CONFIG } from "./config";
export { PrivateKey, PublicKey } from "./keys";

export const utils = {
  aesDecrypt,
  aesEncrypt,
  decodeHex,
  getValidSecret,
  remove0x,
};
