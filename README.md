# eciesjs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/47784cde956642b1b9e8e33cb8551674)](https://app.codacy.com/app/ecies/js)
[![License](https://img.shields.io/github/license/ecies/js.svg)](https://github.com/ecies/js)
[![Npm Package](https://img.shields.io/npm/v/eciesjs.svg)](https://www.npmjs.com/package/eciesjs)
[![CI](https://img.shields.io/github/actions/workflow/status/ecies/js/ci.yml)](https://github.com/ecies/js/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ecies/js.svg)](https://codecov.io/gh/ecies/js)

Elliptic Curve Integrated Encryption Scheme for secp256k1/curve25519 in TypeScript.

This is the JavaScript/TypeScript version of [eciespy](https://github.com/ecies/py) with a built-in class-like secp256k1/curve25519 [API](#privatekey), you may go there for detailed documentation and learn the mechanism under the hood.

If you want a WASM version to run directly in modern browsers or on some blockchains, check [`ecies-wasm`](https://github.com/ecies/rs-wasm).

## Install

```bash
npm install eciesjs
```

We recommend using the latest Node runtime although it's still possible to install on old versions.

## Quick Start

Run the code below with `npx ts-node`.

```typescript
> import { encrypt, decrypt, PrivateKey } from 'eciesjs'
> const sk = new PrivateKey()
> const data = Buffer.from('hello world🌍')
> decrypt(sk.secret, encrypt(sk.publicKey.toHex(), data)).toString()
'hello world🌍'
```

See [Configuration](#configuration) to control with more granularity.

## API

### `encrypt(receiverRawPK: string | Uint8Array, msg: Uint8Array): Buffer`

Parameters:

- **receiverRawPK** - Receiver's public key, hex string or buffer
- **msg** - Data to encrypt

Returns: **Buffer**

### `decrypt(receiverRawSK: string | Uint8Array, msg: Uint8Array): Buffer`

Parameters:

- **receiverRawSK** - Receiver's private key, hex string or buffer
- **msg** - Data to decrypt

Returns: **Buffer**

### `PrivateKey`

- Methods

```typescript
static fromHex(hex: string): PrivateKey;
constructor(secret?: Uint8Array);
toHex(): string;
encapsulate(pk: PublicKey): Uint8Array;
multiply(pk: PublicKey, compressed?: boolean): Uint8Array;
equals(other: PrivateKey): boolean;
```

- Properties

```typescript
get secret(): Buffer;
readonly publicKey: PublicKey;
private readonly data;
```

### `PublicKey`

- Methods

```typescript
static fromHex(hex: string): PublicKey;
constructor(data: Uint8Array);
toHex(compressed?: boolean): string;
decapsulate(sk: PrivateKey): Uint8Array;
equals(other: PublicKey): boolean;
```

- Properties

```typescript
get uncompressed(): Buffer;
get compressed(): Buffer;
private readonly data;
```

## Configuration

Following configurations are available.

- Elliptic curve: secp256k1 or curve25519 (x25519/ed25519)
- Ephemeral key format in the payload: compressed or uncompressed (only for secp256k1)
- Shared elliptic curve key format in the key derivation: compressed or uncompressed (only for secp256k1)
- Symmetric cipher algorithm: AES-256-GCM or XChaCha20-Poly1305
- Symmetric nonce length: 12 or 16 bytes (only for AES-256-GCM)

For compatibility, make sure different applications share the same configuration.

```ts
export type EllipticCurve = "secp256k1" | "x25519" | "ed25519";
export type SymmetricAlgorithm = "aes-256-gcm" | "xchacha20";
export type NonceLength = 12 | 16;

class Config {
  ellipticCurve: EllipticCurve = "secp256k1";
  isEphemeralKeyCompressed: boolean = false;
  isHkdfKeyCompressed: boolean = false;
  symmetricAlgorithm: SymmetricAlgorithm = "aes-256-gcm";
  symmetricNonceLength: NonceLength = 16;
}

export const ECIES_CONFIG = new Config();
```

### Elliptic curve configuration

On `ellipticCurve = "x25519"` or `ellipticCurve = "ed25519"`, x25519 (key exchange function on curve25519) or ed25519 (signature algorithm on curve25519) will be used for key exchange instead of secp256k1.

In this case, the payload would always be: `32 Bytes + Ciphered` regardless of `isEphemeralKeyCompressed`.

> If you don't know how to choose between x25519 and ed25519, just use the dedicated key exchange function x25519 for efficiency.

### Secp256k1-specific configuration

On `isEphemeralKeyCompressed = true`, the payload would be: `33 Bytes + Ciphered` instead of `65 Bytes + Ciphered`.

On `isHkdfKeyCompressed = true`, the hkdf key would be derived from `ephemeral public key (compressed) + shared public key (compressed)` instead of `ephemeral public key (uncompressed) + shared public key (uncompressed)`.

### Symmetric cipher configuration

On `symmetricAlgorithm = "xchacha20"`, plaintext data would be encrypted with XChaCha20-Poly1305.

On `symmetricNonceLength = 12`, the nonce of AES-256-GCM would be 12 bytes. XChaCha20-Poly1305's nonce is always 24 bytes regardless of `symmetricNonceLength`.

## Security Audit

Following dependencies are audited:

- [noble-curves](https://github.com/paulmillr/noble-curves/tree/main/audit)
- [noble-hashes](https://github.com/paulmillr/noble-hashes#security)

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).
