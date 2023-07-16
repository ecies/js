import { ephemeralKeySize, isEphemeralKeyCompressed } from "./config";
import { PrivateKey, PublicKey } from "./keys";
import { aesDecrypt, aesEncrypt, decodeHex, getValidSecret, remove0x } from "./utils";

export function encrypt(receiverRawPK: string | Buffer, msg: Buffer): Buffer {
  const ephemeralKey = new PrivateKey();

  const receiverPK =
    receiverRawPK instanceof Buffer
      ? new PublicKey(receiverRawPK)
      : PublicKey.fromHex(receiverRawPK);

  const aesKey = ephemeralKey.encapsulate(receiverPK);
  const encrypted = aesEncrypt(aesKey, msg);

  if (isEphemeralKeyCompressed()) {
    return Buffer.concat([ephemeralKey.publicKey.compressed, encrypted]);
  } else {
    return Buffer.concat([ephemeralKey.publicKey.uncompressed, encrypted]);
  }
}

export function decrypt(receiverRawSK: string | Buffer, msg: Buffer): Buffer {
  const receiverSK =
    receiverRawSK instanceof Buffer
      ? new PrivateKey(receiverRawSK)
      : PrivateKey.fromHex(receiverRawSK);

  const keySize = ephemeralKeySize();
  const senderPubkey = new PublicKey(msg.subarray(0, keySize));
  const encrypted = msg.subarray(keySize);
  const aesKey = senderPubkey.decapsulate(receiverSK);
  return aesDecrypt(aesKey, encrypted);
}

export { PrivateKey, PublicKey } from "./keys";

export const utils = {
  aesDecrypt,
  aesEncrypt,
  decodeHex,
  getValidSecret,
  remove0x,
};
