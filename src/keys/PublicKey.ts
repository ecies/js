import { secp256k1 } from "@noble/curves/secp256k1";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ONE, UNCOMPRESSED_PUBLIC_KEY_SIZE } from "../consts";
import { decodeHex } from "../utils";
import PrivateKey from "./PrivateKey";

export default class PublicKey {
  public static fromHex(hex: string): PublicKey {
    const decoded = decodeHex(hex);
    if (decoded.length === UNCOMPRESSED_PUBLIC_KEY_SIZE - 1) {
      // eth public key
      const prefix: Buffer = Buffer.from([0x04]);
      const fixed: Buffer = Buffer.concat([prefix, decoded]);
      return new PublicKey(fixed);
    }
    return new PublicKey(decoded);
  }

  public readonly uncompressed: Buffer;
  public readonly compressed: Buffer;

  constructor(buffer: Buffer) {
    this.uncompressed = Buffer.from(secp256k1.getSharedSecret(ONE, buffer, false));
    this.compressed = Buffer.from(secp256k1.getSharedSecret(ONE, buffer, true));
  }

  public toHex(compressed: boolean = true): string {
    if (compressed) {
      return this.compressed.toString("hex");
    } else {
      return this.uncompressed.toString("hex");
    }
  }

  public decapsulate(priv: PrivateKey): Buffer {
    const master = Buffer.concat([this.uncompressed, priv.multiply(this)]);
    return Buffer.from(hkdf(sha256, master, undefined, undefined, 32));
  }

  public equals(other: PublicKey): boolean {
    return this.uncompressed.equals(other.uncompressed);
  }
}
