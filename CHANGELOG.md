
# Changelog

## 0.4.14

- Bump dependencies
- Add details

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
