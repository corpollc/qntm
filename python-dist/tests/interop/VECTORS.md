# Ed25519 → X25519 Interop Test Vectors

These vectors verify cross-project compatibility for Ed25519 identity key → X25519 encryption key derivation using the birational equivalence (RFC 7748 §4.1).

Any implementation that converts Ed25519 public keys to X25519 public keys for Diffie-Hellman key agreement should produce identical results.

## Target Projects
- **qntm** (`python-dist/src/qntm/crypto.py` → `ed25519_public_key_to_x25519()`)
- **agent-passport-system** (`src/core/encrypted-messaging.ts` → `createEncryptionKeypair()`)

## Vectors

### Vector 1 (zero seed)
```
seed:       0000000000000000000000000000000000000000000000000000000000000000
ed25519_pk: 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
x25519_pk:  5bf55c73b82ebe22be80f3430667af570fae2556a6415e6b30d4065300aa947d
```

### Vector 2 (incrementing bytes)
```
seed:       0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
ed25519_pk: 79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664
x25519_pk:  4a3807d064d077181cc070989e76891d20dca5559548dc2c77c1a50273882b38
```

### Vector 3 (all 0xFF)
```
seed:       ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ed25519_pk: 76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5
x25519_pk:  d1fa3f01826bd8b78e057c086c7b22c7ad4358ca918099cd7b7e5d3acd7e285b
```

### Vector 4 (RFC 8032 test vector 1 seed)
```
seed:       9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
ed25519_pk: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
x25519_pk:  d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e
```

### Vector 5 (random)
```
seed:       a3c4e2f1b8d7954c6e0f3a2b1d4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
ed25519_pk: ea21e5719500ca99648e2693eec7dd40ff1ace600f5a70a1071f797be6d23316
x25519_pk:  2eb1f20188c191df7f49958c80baebd923f9f88fe3e5bbf79cc1201a417f3b38
```

## How to Verify

### qntm (Python)
```bash
cd python-dist
uv run pytest tests/interop/test_ed25519_x25519_vectors.py -v
```

### APS (TypeScript/Node)
```typescript
import { createEncryptionKeypair } from 'agent-passport-system';

// Feed the same Ed25519 seed, compare X25519 public key output
const seed = Buffer.from('0000...', 'hex');
const keypair = createEncryptionKeypair(seed);
// keypair.x25519PublicKey should equal the x25519_pk above
```

## Math
The conversion uses the birational map from the twisted Edwards curve (Ed25519) to Montgomery form (Curve25519):
```
u = (1 + y) / (1 - y)  mod p
```
where `y` is the y-coordinate of the Ed25519 public key point, and `p = 2^255 - 19`.
