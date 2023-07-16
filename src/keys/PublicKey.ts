import { isHkdfKeyCompressed } from "../config";
import { ETH_PUBLIC_KEY_SIZE, ONE } from "../consts";
import { decodeHex, deriveKey, getSharedPoint } from "../utils";
import PrivateKey from "./PrivateKey";

export default class PublicKey {
  public static fromHex(hex: string): PublicKey {
    const decoded = decodeHex(hex);
    if (decoded.length === ETH_PUBLIC_KEY_SIZE) {
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
    this.uncompressed = getSharedPoint(ONE, buffer, false);
    this.compressed = getSharedPoint(ONE, buffer, true);
  }

  public toHex(compressed: boolean = true): string {
    if (compressed) {
      return this.compressed.toString("hex");
    } else {
      return this.uncompressed.toString("hex");
    }
  }

  public decapsulate(priv: PrivateKey): Buffer {
    let master: Buffer;

    if (isHkdfKeyCompressed()) {
      master = Buffer.concat([this.compressed, priv.multiply(this, true)]);
    } else {
      master = Buffer.concat([this.uncompressed, priv.multiply(this, false)]);
    }
    return deriveKey(master);
  }

  public equals(other: PublicKey): boolean {
    return this.uncompressed.equals(other.uncompressed);
  }
}
