import { PrivateKey, PublicKey } from "./keys";
import {
  aesDecrypt,
  aesEncrypt,
  decodeHex,
  getValidSecret,
  remove0x,
} from "./utils";
import { UNCOMPRESSED_PUBLIC_KEY_SIZE } from "./consts";

export function encrypt(receiverRawPK: string | Buffer, msg: Buffer): Buffer {
  const ephemeralKey = new PrivateKey();

  const receiverPK =
    receiverRawPK instanceof Buffer
      ? new PublicKey(receiverRawPK)
      : PublicKey.fromHex(receiverRawPK);

  const aesKey = ephemeralKey.encapsulate(receiverPK);
  const encrypted = aesEncrypt(aesKey, msg);
  return Buffer.concat([ephemeralKey.publicKey.uncompressed, encrypted]);
}

export function decrypt(receiverRawSK: string | Buffer, msg: Buffer): Buffer {
  const receiverSK =
    receiverRawSK instanceof Buffer
      ? new PrivateKey(receiverRawSK)
      : PrivateKey.fromHex(receiverRawSK);

  const senderPubkey = new PublicKey(
    msg.slice(0, UNCOMPRESSED_PUBLIC_KEY_SIZE)
  );
  const encrypted = msg.slice(UNCOMPRESSED_PUBLIC_KEY_SIZE);
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
