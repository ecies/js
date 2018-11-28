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
> const k = new PrivateKey()
> const data = Buffer.from('this is a test')
> decrypt(k.toHex(), encrypt(k.publicKey.toHex(), data)).toString()
'this is a test'
```

## API

### `eciesjs.encrypt(receiverPubhex: string, msg: Buffer): Buffer`

Parameters:

-   **receiverPubhex** - Receiver's secp256k1 public key hex string
-   **msg** - Data to encrypt

Returns:  **Buffer**

### `eciesjs.decrypt(receiverPrvhex: string, msg: Buffer): Buffer`

Parameters:

-   **receiverPrvhex** - Receiver's secp256k1 private key hex string
-   **msg** - Data to decrypt

Returns:  **Buffer**
