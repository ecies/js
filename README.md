# eciesjs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/47784cde956642b1b9e8e33cb8551674)](https://app.codacy.com/app/ecies/js)
[![License](https://img.shields.io/github/license/ecies/js.svg)](https://github.com/ecies/js)
[![Npm Package](https://img.shields.io/npm/v/eciesjs.svg)](https://www.npmjs.com/package/eciesjs)
[![CI](https://img.shields.io/github/actions/workflow/status/ecies/js/ci.yml)](https://github.com/ecies/js/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ecies/js.svg)](https://codecov.io/gh/ecies/js)

Elliptic Curve Integrated Encryption Scheme for secp256k1 in TypeScript.

This is the JavaScript/TypeScript version of [eciespy](https://github.com/ecies/py) with a built-in class-like secp256k1 [API](#privatekey), you may go there for detailed documentation and learn the mechanism under the hood.

If you want a WASM version to run directly in modern browsers or on some blockchains, check [`ecies-wasm`](https://github.com/ecies/rs-wasm).

## Install

```bash
npm install eciesjs
```

## Quick Start

Run the code below with `npx ts-node`.

```typescript
> import { encrypt, decrypt, PrivateKey } from 'eciesjs'
> const k1 = new PrivateKey()
> const data = Buffer.from('this is a test')
> decrypt(k1.toHex(), encrypt(k1.publicKey.toHex(), data)).toString()
'this is a test'
```

## API

### `encrypt(receiverRawPK: string | Buffer, msg: Buffer): Buffer`

Parameters:

- **receiverRawPK** - Receiver's secp256k1 public key, hex string or buffer
- **msg** - Data to encrypt

Returns: **Buffer**

### `decrypt(receiverRawSK: string | Buffer, msg: Buffer): Buffer`

Parameters:

- **receiverRawSK** - Receiver's secp256k1 private key, hex string or buffer
- **msg** - Data to decrypt

Returns: **Buffer**

### `PrivateKey`

- Methods

```typescript
static fromHex(hex: string): PrivateKey;
constructor(secret?: Buffer);
toHex(): string;
encapsulate(pub: PublicKey): Buffer;
multiply(pub: PublicKey): Buffer;
equals(other: PrivateKey): boolean;
```

- Properties

```typescript
readonly secret: Buffer;
readonly publicKey: PublicKey;
```

### `PublicKey`

- Methods

```typescript
static fromHex(hex: string): PublicKey;
constructor(buffer: Buffer);
toHex(compressed?: boolean): string;
decapsulate(priv: PrivateKey): Buffer;
equals(other: PublicKey): boolean;
```

- Properties

```typescript
readonly uncompressed: Buffer;
readonly compressed: Buffer;
```

## Configuration

Ephemeral key format in the payload and shared key in the key derivation can be configured as compressed or uncompressed format.

```ts
export type SymmetricAlgorithm = "aes-256-gcm" | "xchacha20";
export type NonceLength = 12 | 16; // bytes. Only for aes-256-gcm

class Config {
  isEphemeralKeyCompressed: boolean = false;
  isHkdfKeyCompressed: boolean = false;
  symmetricAlgorithm: SymmetricAlgorithm = "aes-256-gcm";
  symmetricNonceLength: NonceLength = 16;
}

export const ECIES_CONFIG = new Config();
```

For example, if you set `isEphemeralKeyCompressed = true`, the payload would be like: `33 Bytes + AES` instead of `65 Bytes + AES`.

If you set `isHkdfKeyCompressed = true`, the hkdf key would be derived from `ephemeral public key (compressed) + shared public key (compressed)` instead of `ephemeral public key (uncompressed) + shared public key (uncompressed)`.

If you set `symmetricAlgorithm = "xchacha20"`, plaintext data will encrypted with XChacha20-Poly1305.

If you set `symmetricNonceLength = 12`, then the nonce of aes-256-gcm would be 12 bytes. XChacha20-Poly1305's nonce is always 24 bytes.

For compatibility, make sure different applications share the same configuration.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).
