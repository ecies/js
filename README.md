# eciesjs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/47784cde956642b1b9e8e33cb8551674)](https://app.codacy.com/app/ecies/js)
[![License](https://img.shields.io/github/license/ecies/js.svg)](https://github.com/ecies/js)
[![Npm Package](https://img.shields.io/npm/v/eciesjs.svg)](https://www.npmjs.com/package/eciesjs)
[![Circle CI](https://img.shields.io/circleci/project/ecies/js/master.svg)](https://circleci.com/gh/ecies/js)
[![Codecov](https://img.shields.io/codecov/c/github/ecies/js.svg)](https://codecov.io/gh/ecies/js)

Elliptic Curve Integrated Encryption Scheme for secp256k1, written in TypeScript with **minimal** dependencies.

This is the JavaScript/TypeScript version of [eciespy](https://github.com/kigawas/eciespy) with a built-in class-like secp256k1 [API](#privatekey), you may go there for detailed documentation of the mechanism under the hood.

## Install

Install with `npm install eciesjs`

## Quick Start

```typescript
> import { encrypt, decrypt, PrivateKey } from 'eciesjs'
> const k1 = new PrivateKey()
> const data = Buffer.from('this is a test')
> decrypt(k1.toHex(), encrypt(k1.publicKey.toHex(), data)).toString()
'this is a test'
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

-   Methods

```typescript
static fromHex(hex: string): PrivateKey;
constructor(secret?: Buffer);
toHex(): string;
encapsulate(pub: PublicKey): Buffer;
multiply(pub: PublicKey): Buffer;
equals(other: PrivateKey): boolean;
```

-   Properties

```typescript
readonly secret: Buffer;
readonly publicKey: PublicKey;
```

### `PublicKey`

-   Methods

```typescript
static fromHex(hex: string): PublicKey;
constructor(buffer: Buffer);
toHex(compressed?: boolean): string;
decapsulate(priv: PrivateKey): Buffer;
equals(other: PublicKey): boolean;
```

-   Properties

```typescript
readonly uncompressed: Buffer;
readonly compressed: Buffer;
```
