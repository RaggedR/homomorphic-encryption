# Homomorphic Encryption & Zero-Knowledge Proofs

From-scratch Python implementations of two foundational cryptographic primitives. No external dependencies — just `math`, `random`, and `hashlib`.

## Paillier Encrypted Polling

The [Paillier cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem) has an additive homomorphic property: multiplying ciphertexts adds plaintexts.

```
E(m1) * E(m2) mod n^2 = E(m1 + m2)
```

This means a server can tally encrypted votes without ever seeing a single vote.

```bash
python3 paillier_poll.py
```

**What it demonstrates:**
- Key generation (512-bit)
- Encrypting individual yes/no votes
- Server-side homomorphic tallying (multiply ciphertexts, decrypt the product)
- Semantic security (same plaintext, different ciphertext every time)
- Multi-candidate polls using positional encoding

## Schnorr Zero-Knowledge Proof

The [Schnorr protocol](https://en.wikipedia.org/wiki/Schnorr_signature) proves you know a secret key without revealing it.

Given public key `y = g^x mod p`, prove you know `x` in three messages:
1. **Commit**: prover sends `t = g^k` (random k)
2. **Challenge**: verifier sends random `c`
3. **Respond**: prover sends `s = k - c*x mod q`

Verification: `g^s * y^c == t`. The verifier is convinced, but learns nothing about `x`.

```bash
python3 schnorr_zkp.py
```

**What it demonstrates:**
- Interactive protocol (5 rounds, all pass)
- A cheating prover (wrong secret) getting caught
- Non-interactive variant via the [Fiat-Shamir transform](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic) (replace verifier's challenge with a hash)
- Tampered proofs and wrong keys correctly rejected
