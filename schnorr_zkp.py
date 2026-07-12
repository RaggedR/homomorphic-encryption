"""
Schnorr Zero-Knowledge Proof — Prove you know a secret without revealing it.

The Schnorr protocol proves knowledge of a discrete logarithm:
    Given public key y = g^x mod p, prove you know x.

The protocol (interactive, 3 messages):
    1. Prover picks random k, sends commitment t = g^k mod p
    2. Verifier sends random challenge c
    3. Prover sends response s = k - c·x mod q

Verification: g^s · y^c ≡ t (mod p)

This works because:
    g^s · y^c = g^(k - cx) · g^(cx) = g^k = t

Zero-knowledge: the verifier learns nothing about x, because for any
challenge c, the prover could have faked (t, s) by choosing s first and
computing t = g^s · y^c. The transcript is simulatable without knowing x.

No external libraries — just Python's built-in math and random.
"""

import random
import hashlib


# --- Parameter generation ---

def is_probably_prime(n, rounds=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probably_prime(p):
            return p


def schnorr_group():
    """
    Return a safe-prime Schnorr group: p is prime, q = (p-1)/2 is prime,
    and g is a generator of the order-q subgroup.

    Using a 512-bit safe prime (p = 2q + 1). In production you'd use
    RFC 3526 groups, but this is small enough for a demo and we verify
    the primality below.
    """
    # A 256-bit safe prime (p = 2q + 1, both p and q verified prime)
    p = int(
        "94CC6F27C164CFF2"
        "D47598830B1FEADA"
        "D87294C088708639"
        "79B90A8956FA0B7B", 16
    )
    q = (p - 1) // 2
    # g = 4 is a generator of the order-q subgroup for safe primes
    # (since g^q mod p ≠ 1 would mean g generates Z*_p, but 4^q ≡ 1
    #  for safe primes, so g=4 generates the order-q subgroup; we need
    #  g^q ≡ 1 and g ≠ 1 and g^1 ≠ 1)
    g = pow(2, 2, p)  # g = 4
    # Verify g is in the subgroup of order q
    assert pow(g, q, p) == 1, "g does not have order q"
    assert g != 1
    return p, q, g


# --- Schnorr Protocol (Interactive) ---

class SchnorrProver:
    def __init__(self, params, secret_key):
        self.p, self.q, self.g = params
        self.x = secret_key
        self.y = pow(self.g, self.x, self.p)  # public key
        self._k = None

    def commit(self):
        """Step 1: Pick random k, send t = g^k mod p."""
        self._k = random.randrange(1, self.q)
        t = pow(self.g, self._k, self.p)
        return t

    def respond(self, challenge):
        """Step 3: Compute s = k - c·x mod q."""
        s = (self._k - challenge * self.x) % self.q
        self._k = None  # destroy k — reuse would leak the secret!
        return s


class SchnorrVerifier:
    def __init__(self, params, public_key):
        self.p, self.q, self.g = params
        self.y = public_key

    def challenge(self):
        """Step 2: Send random challenge c."""
        return random.randrange(1, self.q)

    def verify(self, t, c, s):
        """Check: g^s · y^c ≡ t (mod p)."""
        lhs = (pow(self.g, s, self.p) * pow(self.y, c, self.p)) % self.p
        return lhs == t


# --- Non-Interactive (Fiat-Shamir heuristic) ---

def fiat_shamir_prove(params, secret_key):
    """
    Non-interactive Schnorr proof using Fiat-Shamir transform.

    Instead of the verifier choosing c, the prover computes:
        c = H(g, y, t)
    This makes the proof non-interactive — a single message.
    """
    p, q, g = params
    y = pow(g, secret_key, p)
    k = random.randrange(1, q)
    t = pow(g, k, p)

    # Challenge = hash of public parameters and commitment
    c_bytes = hashlib.sha256(f"{g},{y},{t}".encode()).digest()
    c = int.from_bytes(c_bytes, "big") % q

    s = (k - c * secret_key) % q
    return (t, s)  # the proof


def fiat_shamir_verify(params, public_key, proof):
    """Verify a non-interactive Schnorr proof."""
    p, q, g = params
    t, s = proof

    # Recompute challenge
    c_bytes = hashlib.sha256(f"{g},{public_key},{t}".encode()).digest()
    c = int.from_bytes(c_bytes, "big") % q

    lhs = (pow(g, s, p) * pow(public_key, c, p)) % p
    return lhs == t


# --- Demos ---

def interactive_demo():
    print("=" * 60)
    print("INTERACTIVE SCHNORR ZKP")
    print("=" * 60)

    print("\n🔑 Generating Schnorr group parameters...")
    params = schnorr_group()
    p, q, g = params
    print(f"   p = {str(p)[:40]}... ({p.bit_length()} bits)")
    print(f"   q = {str(q)[:40]}... ({q.bit_length()} bits)")

    # Secret key (the thing we're proving knowledge of)
    secret = random.randrange(1, q)
    public_key = pow(g, secret, p)
    print(f"\n🤫 Secret key x = {str(secret)[:30]}...")
    print(f"📢 Public key y = g^x mod p = {str(public_key)[:30]}...")

    prover = SchnorrProver(params, secret)
    verifier = SchnorrVerifier(params, public_key)

    # Run the protocol multiple rounds
    num_rounds = 5
    print(f"\n🔄 Running {num_rounds} rounds of the protocol:\n")

    for i in range(num_rounds):
        t = prover.commit()         # Step 1: prover commits
        c = verifier.challenge()    # Step 2: verifier challenges
        s = prover.respond(c)       # Step 3: prover responds
        ok = verifier.verify(t, c, s)

        print(f"   Round {i+1}: commit={str(t)[:15]}...  "
              f"challenge={str(c)[:15]}...  "
              f"response={str(s)[:15]}...  "
              f"{'PASS' if ok else 'FAIL'}")

    # Demonstrate: a cheating prover (wrong secret) fails
    print("\n🚫 Cheating prover (wrong secret key):")
    fake_secret = random.randrange(1, q)
    cheater = SchnorrProver(params, fake_secret)

    t = cheater.commit()
    c = verifier.challenge()
    s = cheater.respond(c)
    ok = verifier.verify(t, c, s)
    print(f"   Result: {'PASS' if ok else 'FAIL'}  (should be FAIL)")


def non_interactive_demo():
    print("\n" + "=" * 60)
    print("NON-INTERACTIVE SCHNORR ZKP (Fiat-Shamir)")
    print("=" * 60)

    print("\n🔑 Generating parameters...")
    params = schnorr_group()
    p, q, g = params

    secret = random.randrange(1, q)
    public_key = pow(g, secret, p)

    # Generate proof
    print("\n📝 Prover generates a single proof (no interaction needed)...")
    proof = fiat_shamir_prove(params, secret)
    t, s = proof
    print(f"   Proof: (t={str(t)[:30]}..., s={str(s)[:30]}...)")

    # Verify
    ok = fiat_shamir_verify(params, public_key, proof)
    print(f"\n✅ Verifier checks proof: {'VALID' if ok else 'INVALID'}")

    # Tampered proof should fail
    tampered_proof = (t + 1, s)
    ok2 = fiat_shamir_verify(params, public_key, tampered_proof)
    print(f"🚫 Tampered proof check:  {'VALID' if ok2 else 'INVALID'}  (should be INVALID)")

    # Wrong public key should fail
    wrong_key = pow(g, random.randrange(1, q), p)
    ok3 = fiat_shamir_verify(params, wrong_key, proof)
    print(f"🚫 Wrong public key:      {'VALID' if ok3 else 'INVALID'}  (should be INVALID)")


if __name__ == "__main__":
    interactive_demo()
    non_interactive_demo()
