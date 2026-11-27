# Changelog

## 0.5.1

- Bump dependencies
- Wipe secrets once they're used, best effort: the HKDF input in `getSharedKey`, the shared point in `encapsulate` and `decapsulate`, the derived key in `encrypt` and `decrypt`, the ephemeral secret key in `encrypt`, and on ed25519 the two halves of the hashed secret key that noble returns to `getPublicKey` and `getSharedPoint`
  - Copies that noble and `@ecies/ciphers` make inside their own calls stay out of reach
- Refuse ed25519 public keys that are small-order or have a small-order component, in `encrypt`, `decrypt` and wherever else a public key meets a secret key
- Decode secp256k1 public keys without a scalar multiplication, making `encrypt` and `decrypt` about 4x faster
- `new PublicKey` and `new PrivateKey` now refuse anything but a `Uint8Array` on every curve
  - `new PublicKey` used to accept a hex string without `0x` on secp256k1, and keep whatever it was given as the key on x25519 and ed25519
  - `new PrivateKey` used to keep a hex string without `0x` as the key on every curve, and a bigint on secp256k1
  - Use `PublicKey.fromHex` and `PrivateKey.fromHex` for hex
- `convertPublicKeyFormat` now refuses a hex string on secp256k1

## 0.5.0

- API change: `encrypt/decrypt` now always returns a `Uint8Array` instead of a `Buffer`
- API change: `symEncrypt/symDecrypt` now accept an optional `Config` parameter instead of relying on the global `ECIES_CONFIG`
  - It fixed a bug caused by config discrepancy between `encrypt/decrypt` and `symEncrypt/symDecrypt`
- Remove deprecated APIs and `utils` re-exports
- Bump dependencies
- Bump emitted JavaScript target to es2021

## 0.4.18

- Bump dependencies
- Prepare for v0.5.0
  - API change: Return a Node.js `Buffer` only when available (otherwise a `Uint8Array`)

## 0.4.17

- Bump dependencies
- Prepare for ESM

## 0.4.16

- Bump dependencies
- Drop Node 18 support
- Remove deprecated `@noble/curves` usage

## 0.4.15

- Bump dependencies
- Revamp documentation
- Make `curve` configurable in `keys` and `utils` via argument

## 0.4.14

- Bump dependencies
- Add details
- Revamp documentation

## 0.4.13

- Bump dependencies

## 0.4.12

- Add `PublicKey.toBytes` and deprecate `PublicKey.compressed` and `PublicKey.uncompressed`
- Save uncompressed public key data for secp256k1

## 0.4.11

- Revamp encapsulate/decapsulate
- Revamp symmetric encryption/decryption
- Revamp elliptic utils
- Add browser tests

## 0.4.10

- Fix commonjs build

## 0.4.9

- Add examples
- Update documentation
- Migrate to [vitest](https://vitest.dev/)
- Export all modules to allow full customization
- Introduce [`@ecies/ciphers`](https://github.com/ecies/js-ciphers) as symmetric cipher adapter for different platforms
  - Use pure JS (`@noble/ciphers`) AES implementation if running in browsers to improve compatibility
  - Use `node:crypto`'s chacha20 implementation on Node runtime to improve performance

## 0.4.1 ~ 0.4.8

- Revamp util functions
- Drop Node 16 support
- Support curve25519 (x25519 and ed25519) tentatively
- Revamp browser compatibility
- Fix symmetric encryption internal types
- Add XChaCha20 as an optional encryption backend
- Add configuration for more compatibility
- Bump dependencies

## 0.4.0

- Change secp256k1 library to audited [noble-curves](https://github.com/paulmillr/noble-curves)
- Change hash library to audited [noble-hashes](https://github.com/paulmillr/noble-hashes)
- Change test library to [jest](https://jestjs.io/)
- Bump dependencies
- Drop Node 14 support

## 0.3.1 ~ 0.3.21

- Revamp tests
- Support Node 18, 20
- Drop Node 10, 12 support
- Bump dependencies
- Update documentation
- Extract constant variables and rename some parameters
- Revamp CI
- Migrate to vitest

## 0.3.0

- API change: `encrypt/decrypt` now can take both hex `string` and `Buffer`

## 0.2.0

- API change: use `HKDF-sha256` to derive shared keys instead of `sha256`
- Bump dependencies
- Update documentation

## 0.1.1 ~ 0.1.5

- Bump dependencies
- Update documentation

## 0.1.0

- First beta version release
