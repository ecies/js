# AGENTS.md - eciesjs

## Purpose

TypeScript implementation of ECIES (Elliptic Curve Integrated Encryption Scheme) providing public-key encryption using elliptic curves.

**Domain**: Cryptographic library combining ECDH key exchange with symmetric AEAD encryption.

**Dependencies**:

- `@noble/curves` - Elliptic curve operations (secp256k1, x25519, ed25519)
- `@noble/ciphers` - Symmetric encryption fallback (AES-GCM, ChaCha20)
- `@noble/hashes` - HKDF-SHA256 key derivation

**Targets**: Node.js 16+, Bun 1+, Deno 2+, Browsers, React Native

---

## Critical Constraints

- NEVER use `any` types - TypeScript is configured with maximum strictness
- ALWAYS use `.js` extensions in import paths (ESM requirement)
- NEVER modify encryption payload format without updating both encrypt AND decrypt
- ALWAYS maintain backward compatibility with existing encrypted data
- Configuration changes (compression, nonce length) must match between sender/receiver
- Use only audited crypto libraries (@noble/\*)
- Private keys MUST be validated before use (secp256k1 requires range check)

---

## Architecture

### Directory Structure

```sh
src/
├── index.ts          # Main exports: encrypt(), decrypt()
├── config.ts         # ECIES_CONFIG singleton, types
├── consts.ts         # Key sizes, nonce lengths
├── keys/
│   ├── PrivateKey.ts # Secret key handling
│   └── PublicKey.ts  # Public key with compression
├── utils/
│   ├── elliptic.ts   # ECDH operations via _exec()
│   ├── symmetric.ts  # symEncrypt/symDecrypt
│   ├── hash.ts       # HKDF key derivation
│   └── hex.ts        # Hex encoding utilities
└── ciphers/
    ├── index.ts      # Platform detection, cipher factory
    ├── aes.node.ts   # Native Node.js AES
    ├── aes.noble.ts  # @noble/ciphers AES fallback
    ├── chacha.node.ts # Native ChaCha20
    ├── chacha.noble.ts # @noble fallback
    └── _hchacha.ts   # XChaCha20 nonce extension
```

### Encryption Flow

```sh
encrypt(receiverPK, plaintext)
  → Create ephemeral PrivateKey
  → ECDH: ephemeralSK.encapsulate(receiverPK) → sharedKey
  → HKDF-SHA256(ephemeralPK || sharedPoint) → sessionKey
  → symEncrypt(sessionKey, plaintext)
  → Return: ephemeralPK || nonce || authTag || ciphertext
```

### Payload Format (default secp256k1 + AES-256-GCM)

```sh
| 65 bytes | 16 bytes | 16 bytes | variable |
| ephemPK  | nonce    | authTag  | ciphertext |
```

### Platform Detection (`ciphers/index.ts`)

- Tries `node:crypto` first for native performance
- Falls back to `@noble/ciphers` for browsers/Deno/Bun
- Graceful degradation, no exceptions to caller

---

## Development Patterns

### TypeScript (tsconfig.json)

- `strict: true` with ALL additional strict flags enabled
- `noUncheckedIndexedAccess: true` - array access returns T | undefined
- `exactOptionalPropertyTypes: true` - no implicit undefined
- Zero tolerance for implicit any

### Naming Conventions

- Public functions: `camelCase` (encrypt, decrypt, getValidSecret)
- Internal functions: `_underscore` (\_encrypt,\_decrypt, \_exec)
- Classes: `PascalCase` (PrivateKey, PublicKey, Config)
- Types: `PascalCase` (EllipticCurve, SymmetricAlgorithm)
- Constants: `UPPER_SNAKE_CASE` (SECRET_KEY_LENGTH, ECIES_CONFIG)

### Import Pattern

```typescript
// ALWAYS use .js extension for local imports
import { PrivateKey } from "./keys/PrivateKey.js";
import { ECIES_CONFIG } from "./config.js";

// Type-only imports when possible
import type { EllipticCurve } from "./config.js";
```

### Multi-Curve Support Pattern

```typescript
// Use _exec() helper for curve-polymorphic operations
function _exec<T>(
  curve: EllipticCurve | undefined,
  secp256k1Callback: (curveFn: typeof secp256k1) => T,
  x25519Callback: (curveFn: typeof x25519) => T,
  ed25519Callback: (curveFn: typeof ed25519) => T
): T;
```

### Error Handling

```typescript
// Explicit validation with clear messages
if (!isValidPrivateKey(secret, curve)) {
  throw new Error("Invalid private key");
}
// Exhaustive checks
else {
  throw new Error("Not implemented");
}
```

---

## Testing

### Framework

Vitest with coverage via @vitest/coverage-v8

### Test Structure (mirrors src/)

```sh
tests/
├── crypt/*.test.ts        # encrypt/decrypt round-trips
├── keys/*.test.ts         # Key generation and validation
├── utils/*.test.ts        # Utility function tests
├── ciphers/*.test.ts      # Cipher implementations
├── config.test.ts
└── integration.test.ts    # Cross-compatibility with Python
```

### Test Categories

- `*.random.test.ts` - Randomized data tests
- `*.known.test.ts` - Known vector tests (deterministic)

### Run Tests

```bash
pnpm test              # All tests
pnpm test:browser      # Browser environment tests
pnpm tsc:check         # Type checking only
pnpm check             # Biome lint + format
```

### Coverage Exclusions

- `src/keys/index.ts`, `src/utils/index.ts`, `src/ciphers/index.ts` (re-exports only)

---

## Build System

### Tool

`zshy` - Compiles TypeScript to dual CJS/ESM

### Commands

```bash
pnpm build         # Compile to dist/
pnpm check         # Lint and format check
pnpm check:fix     # Auto-fix lint issues
```

### Output

```sh
dist/
├── index.js / index.cjs     # ESM / CJS main
├── index.d.ts / index.d.cts # Type definitions
└── [submodules]/            # keys/, utils/, ciphers/
```

### Package Exports

- `.` - Main module (encrypt, decrypt, keys, config)
- `./config` - Configuration only
- `./consts` - Constants only
- `./utils` - Low-level utilities

---

## Common Tasks

### Adding a New Symmetric Cipher

1. Create `src/ciphers/newcipher.node.ts` (native) and `newcipher.noble.ts` (fallback)
2. Add cipher type to `SymmetricAlgorithm` in `config.ts`
3. Add branch in `src/utils/symmetric.ts` for new algorithm
4. Update `src/ciphers/index.ts` factory
5. Add tests in `tests/ciphers/newcipher.*.test.ts`
6. Update payload format documentation

### Adding a New Elliptic Curve

1. Add curve type to `EllipticCurve` in `config.ts`
2. Import curve from `@noble/curves`
3. Add callback branch in `_exec()` in `utils/elliptic.ts`
4. Update `ephemeralKeySize` getter in `config.ts`
5. Add tests in `tests/keys/` and `tests/utils/elliptic.*.test.ts`

### Modifying Key Classes

1. Maintain backward compatibility with existing serialization
2. Update both `PrivateKey.ts` and `PublicKey.ts` if they interact
3. Preserve `fromHex()` and `toHex()` compatibility
4. Update `encapsulate()`/`decapsulate()` symmetrically
5. Add tests for new functionality

---

## Security Considerations

- **Ephemeral Keys**: New random key per encryption (forward secrecy)
- **HKDF**: Uses SHA-256 with ephemeral PK as entropy source
- **AEAD**: All ciphers include 16-byte authentication tag
- **Constant-time**: Uses `equalBytes()` for key comparisons
- **Validation**: Private keys validated against curve requirements
- **AES-256-CBC**: Deprecated, included only for legacy compatibility

### Security Gotchas

- Configuration mismatch between sender/receiver causes silent decryption failure
- No algorithm identifier in payload - both parties must use same config
- XChaCha20's 24-byte nonce provides better collision resistance than AES's 12-16 bytes
