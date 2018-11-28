# eciesjs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/ba01a8bb2d3344f29f98157ccbd14519)](https://app.codacy.com/app/kigawas/eciesjs?utm_source=github.com&utm_medium=referral&utm_content=kigawas/eciesjs&utm_campaign=Badge_Grade_Dashboard)
[![License](https://img.shields.io/github/license/kigawas/eciesjs.svg)](https://github.com/kigawas/eciesjs)
[![Npm Package](https://img.shields.io/npm/v/eciesjs.svg)](https://www.npmjs.com/package/eciesjs)
[![Circle CI](https://img.shields.io/circleci/project/kigawas/eciesjs/master.svg)](https://circleci.com/gh/kigawas/eciesjs)
[![Codecov](https://img.shields.io/codecov/c/github/kigawas/eciesjs.svg)](https://codecov.io/gh/kigawas/eciesjs)

Elliptic Curve Integrated Encryption Scheme for secp256k1

This is the JavaScript version of [eciespy](https://github.com/kigawas/eciespy), please go to there for detailed mechanism documentation.

## Install

Install with `npm install eciesjs` (only [`secp256k1`](https://github.com/cryptocoinjs/secp256k1-node) is the dependency).

## Quick Start

```typescript
> import { encrypt, decrypt, PrivateKey, utils } from 'eciesjs'
> const k1 = new PrivateKey()
> const data = Buffer.from('this is a test')
> decrypt(k1.toHex(), encrypt(k1.publicKey.toHex(), data)).toString()
'this is a test'
> utils.sha256(Buffer.from('0')).slice(0, 8)
<Buffer 5f ec eb 66 ff c8 6f 38>
> const k2 = new PrivateKey()
> k1.ecdh(k2.publicKey).equals(k2.ecdh(k1.publicKey))
true
```

## API

### `encrypt(receiverPubhex: string, msg: Buffer): Buffer`

Parameters:

-   **receiverPubhex** - Receiver's secp256k1 public key hex string
-   **msg** - Data to encrypt

Returns:  **Buffer**

### `decrypt(receiverPrvhex: string, msg: Buffer): Buffer`

Parameters:

-   **receiverPrvhex** - Receiver's secp256k1 private key hex string
-   **msg** - Data to decrypt

Returns:  **Buffer**

### `PrivateKey`

```typescript
    static fromHex(hex: string): PrivateKey;
    readonly secret: Buffer;
    readonly publicKey: PublicKey;
    constructor(secret?: Buffer);
    toHex(): string;
    ecdh(pub: PublicKey): Buffer;
    equals(other: PrivateKey): boolean;
```

### `PublicKey`

```typescript
    static fromHex(hex: string): PublicKey;
    readonly uncompressed: Buffer;
    readonly compressed: Buffer;
    constructor(buffer: Buffer);
    toHex(compressed?: boolean): string;
    equals(other: PublicKey): boolean;
```
