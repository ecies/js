/// <reference types="node" />
export default class PublicKey {
    static fromHex(hex: string): PublicKey;
    readonly uncompressed: Buffer;
    readonly compressed: Buffer;
    constructor(buffer: Buffer);
    toHex(compressed?: boolean): string;
    equals(other: PublicKey): boolean;
}
