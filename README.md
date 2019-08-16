# eciesjs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/47784cde956642b1b9e8e33cb8551674)](https://app.codacy.com/app/ecies/js)
[![License](https://img.shields.io/github/license/ecies/js.svg)](https://github.com/ecies/js)
[![Npm Package](https://img.shields.io/npm/v/eciesjs.svg)](https://www.npmjs.com/package/eciesjs)
[![Circle CI](https://img.shields.io/circleci/project/ecies/js/master.svg)](https://circleci.com/gh/ecies/js)
[![Codecov](https://img.shields.io/codecov/c/github/ecies/js.svg)](https://codecov.io/gh/ecies/js)

Elliptic Curve Integrated Encryption Scheme for secp256k1, written in TypeScript with **minimal** dependencies.

This is the JavaScript/TypeScript version of [eciespy](https://github.com/kigawas/eciespy) with a built-in class-like secp256k1 [API](#privatekey), you may go there for detailed documentation of the mechanism under the hood.

## Install

Install with `npm install eciesjs` ([`secp256k1`](https://github.com/cryptocoinjs/secp256k1-node) is the only dependency).

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

-   Methods

```typescript
static fromHex(hex: string): PrivateKey;
constructor(secret?: Buffer);
toHex(): string;
encapsulateKEM(pub: PublicKey): Buffer;
ecdh(pub: PublicKey): Buffer;
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
decapsulateKEM(priv: PrivateKey): Buffer;
equals(other: PublicKey): boolean;
```

-   Properties

```typescript
readonly uncompressed: Buffer;
readonly compressed: Buffer;
```
