
# Changelog

## 0.4.1 ~ 0.4.5

- Revamp browser compatibility
- Export config
- Fix symmetric encryption internal types
- Add XChaCha20 as an optional encryption backend
- Add configuration for more compatibility
- Bump dependencies

## 0.4.0

- Change secp256k1 library to [noble-curves](https://github.com/paulmillr/noble-curves), which is [audited](https://github.com/paulmillr/noble-curves/tree/main/audit)
- Change hash library to [noble-hashes](https://github.com/paulmillr/noble-hashes)
- Change test library to [jest](https://jestjs.io/)
- Bump dependencies
- Drop Node 14 support

## 0.3.1 ~ 0.3.17

- Support Node 18, 20
- Drop Node 10, 12 support
- Bump dependencies
- Update documentation
- Extract constant variables and rename some parameters

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
