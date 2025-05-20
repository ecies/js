# Mechanism and Implementation in JavaScript

> [!NOTE]
>
> This document is an adapted version of the original document in [eciespy](https://github.com/ecies/py/blob/master/DETAILS.md). You may go there for detailed documentation and learn the mechanism under the hood.

This library combines `secp256k1` and `AES-256-GCM` (powered by [@noble/curves](https://github.com/paulmillr/noble-curves) and [@noble/ciphers](https://github.com/paulmillr/noble-ciphers)) to provide an API for encrypting with `secp256k1` public key and decrypting with `secp256k1`'s private key. It consists of two main parts:

1. Use [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman) to exchange an AES session key;

   > Note that the sender public key is generated every time when `encrypt` is called, thus, the AES session key varies.
   >
   > We use HKDF-SHA256 instead of SHA256 to derive the AES keys for better security.

2. Use this AES session key to encrypt/decrypt the data under `AES-256-GCM`.

The encrypted data structure is as follows:

```plaintext
+-------------------------------+----------+----------+-----------------+
| 65 Bytes                      | 16 Bytes | 16 Bytes | == data size    |
+-------------------------------+----------+----------+-----------------+
| Sender Public Key (ephemeral) | Nonce/IV | Tag/MAC  | Encrypted data  |
+-------------------------------+----------+----------+-----------------+
| sender_pk                     | nonce    | tag      | encrypted_data  |
+-------------------------------+----------+----------+-----------------+
|           Secp256k1           |              AES-256-GCM              |
+-------------------------------+---------------------------------------+
```

## Secp256k1 in JavaScript

### ECDH Implementation

In JavaScript, we use the [@noble/curves](https://github.com/paulmillr/noble-curves) library which provides a pure JavaScript implementation of secp256k1. Here's a basic example:

```typescript
import { secp256k1 } from '@noble/curves/secp256k1';
import { equalBytes } from "@noble/ciphers/utils";

// Generate private keys (in production, use crypto.getRandomValues())
const k1 = 3n;
const k2 = 2n;

// Get public keys
const pub1 = secp256k1.getPublicKey(k1);
const pub2 = secp256k1.getPublicKey(k2);

// Calculate shared secret - both parties will get the same result
const shared1 = secp256k1.getSharedSecret(k1, pub2);
const shared2 = secp256k1.getSharedSecret(k2, pub1);

console.log(equalBytes(shared1, shared2));
// true
```

### Public Key Formats

Just like in the Python implementation, secp256k1 public keys can be represented in compressed (33 bytes) or uncompressed (65 bytes) format:

- Uncompressed format (65 bytes): `04 || x || y`
- Compressed format (33 bytes): `02/03 || x` (02 if y is even, 03 if y is odd)

The library handles both formats seamlessly:

```typescript
import { secp256k1 } from '@noble/curves/secp256k1';

const privateKey = 3n;
const publicKeyUncompressed = secp256k1.getPublicKey(privateKey, false);  // 65 bytes
const publicKeyCompressed = secp256k1.getPublicKey(privateKey, true);     // 33 bytes
```

## AES in JavaScript

For AES encryption, we use [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) which provides a pure JavaScript implementation of AES-GCM. Here's a basic example:

```typescript
import { gcm } from '@noble/ciphers/aes';

// 32-byte key from ECDH
const key = new Uint8Array(32);
// 16-byte nonce
const nonce = new Uint8Array(16);
const data = new TextEncoder().encode('hello world');

// Encrypt
const cipher = gcm(key, nonce);
const encrypted = cipher.encrypt(data);

// Decrypt
const decipher = gcm(key, nonce);
const decrypted = decipher.decrypt(encrypted);

console.log(new TextDecoder().decode(decrypted));
// 'hello world'
```

Note that due to the format difference between @noble/ciphers with Python implementation, we need to adjust the position of nonce and tag in the encrypted data:

```js
const encrypted = cipher.encrypt(data);
const cipherTextLength = encrypted.length - tagLength;
const cipherText = encrypted.subarray(0, cipherTextLength);
const tag = encrypted.subarray(cipherTextLength);
// ecies payload format: pk || nonce || tag || cipherText
const adjustedEncrypted = concatBytes(nonce, tag, cipherText);
```

## Key Derivation

Instead of using plain SHA256 for key derivation, we use HKDF-SHA256 which is more secure:

```typescript
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

// Derive AES key from ECDH shared secret
const ourPrivateKey = 3n;
// const ourPublicKey = secp256k1.getPublicKey(ourPrivateKey);
const theirPrivateKey = 2n;
const theirPublicKey = secp256k1.getPublicKey(theirPrivateKey);

const sharedSecret = secp256k1.getSharedSecret(ourPrivateKey, theirPublicKey);
const sharedKey = hkdf(sha256, sharedSecret, undefined, undefined, 32);
```
