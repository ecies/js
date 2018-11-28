# eciesjs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/3f8cbc3beb094cff82c1abebbc758003)](https://app.codacy.com/app/kigawas/eciesjs?utm_source=github.com&utm_medium=referral&utm_content=kigawas/eciesjs&utm_campaign=Badge_Grade_Dashboard)
[![License](https://img.shields.io/github/license/kigawas/eciesjs.svg)](https://github.com/kigawas/eciesjs)
[![Npm Package](https://img.shields.io/npm/v/eciesjs.svg)](https://www.npmjs.com/package/eciesjs)
[![Circle CI](https://img.shields.io/circleci/project/kigawas/eciesjs/master.svg)](https://circleci.com/gh/kigawas/eciesjs)
[![Codecov](https://img.shields.io/codecov/c/github/kigawas/eciesjs.svg)](https://codecov.io/gh/kigawas/eciesjs)

Elliptic Curve Integrated Encryption Scheme for secp256k1

This is the JavaScript version of [eciespy](https://github.com/kigawas/eciespy)

## Install

Install with `npm install eciesjs`

## Quick Start

```typescript
> import { encrypt, decrypt } from 'eciesjs'
> import { PrivateKey }from 'eciesjs/keys'
> k = new PrivateKey()
> data = Buffer.from('this is a test')
> decrypt(k.toHex(), encrypt(k.publicKey.toHex(), data)).toString()
'this is a test'
```

## API

### `ecies.encrypt(receiver_pubhex: str, msg: bytes) -> bytes`

Parameters:

-   **receiver_pubhex** - Receiver's secp256k1 public key hex string
-   **msg** - Data to encrypt

Returns:  **bytes**

### `ecies.decrypt(receiver_prvhex: str, msg: bytes) -> bytes`

Parameters:

-   **receiver_prvhex** - Receiver's secp256k1 private key hex string
-   **msg** - Data to decrypt

Returns:  **bytes**
