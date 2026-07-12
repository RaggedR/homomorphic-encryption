"""
Paillier Homomorphic Encryption — Encrypted Polling Demo

The Paillier cryptosystem has an additive homomorphic property:
    E(m₁) · E(m₂) mod n² = E(m₁ + m₂)

This means a server can tally encrypted votes by multiplying ciphertexts,
without ever seeing any individual vote.

No external libraries — just Python's built-in math and random.
"""

import math
import random


# --- Utilities ---

def modinv(a, m):
    """Modular inverse via extended Euclidean algorithm."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def is_probably_prime(n, rounds=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    # Write n-1 as 2^r · d
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
    """Generate a random probable prime of the given bit length."""
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1  # ensure top bit and odd
        if is_probably_prime(p):
            return p


# --- Paillier Cryptosystem ---

def generate_keys(bits=512):
    """
    Generate a Paillier key pair.

    Public key:  (n, g)     where n = p·q, g = n+1
    Private key: (lam, mu)  where lam = lcm(p-1, q-1), mu = lam⁻¹ mod n
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    nsq = n * n
    lam = math.lcm(p - 1, q - 1)

    # Simplified: g = n + 1, which makes L(g^λ mod n²) = λ mod n
    g = n + 1
    mu = modinv(lam, n)

    public_key = (n, g)
    private_key = (lam, mu, n)
    return public_key, private_key


def encrypt(public_key, plaintext):
    """
    Encrypt: E(m, r) = g^m · r^n mod n²

    Each encryption uses a fresh random r, so encrypting the same
    value twice gives different ciphertexts (semantic security).
    """
    n, g = public_key
    nsq = n * n

    # Random r ∈ [1, n) with gcd(r, n) = 1
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break

    # g^m · r^n mod n²
    ciphertext = (pow(g, plaintext, nsq) * pow(r, n, nsq)) % nsq
    return ciphertext


def decrypt(private_key, ciphertext):
    """
    Decrypt: D(c) = L(c^λ mod n²) · μ mod n
    where L(x) = (x - 1) / n
    """
    lam, mu, n = private_key
    nsq = n * n
    x = pow(ciphertext, lam, nsq)
    l = (x - 1) // n  # L function — exact integer division
    plaintext = (l * mu) % n
    return plaintext


def add_encrypted(public_key, c1, c2):
    """
    Homomorphic addition: multiply two ciphertexts mod n².
    Decrypting the result gives the sum of the two plaintexts.
    """
    n, _ = public_key
    return (c1 * c2) % (n * n)


# --- Demo ---

def yes_no_poll():
    """Simple yes/no poll: each voter casts 1 (yes) or 0 (no)."""
    print("=" * 60)
    print("ENCRYPTED YES/NO POLL")
    print("=" * 60)

    print("\n🔑 Generating Paillier keys (512-bit)...")
    public_key, private_key = generate_keys(bits=512)
    n, g = public_key
    print(f"   n = {str(n)[:40]}... ({n.bit_length()} bits)")

    # Simulate 10 voters
    num_voters = 10
    votes = [random.choice([0, 1]) for _ in range(num_voters)]
    print(f"\n📊 {num_voters} voters cast their ballots:")
    print(f"   Plaintext votes: {votes}")
    print(f"   Actual tally:    {sum(votes)} yes, {num_voters - sum(votes)} no")

    # Each voter encrypts their vote
    print("\n🔒 Encrypting individual votes...")
    encrypted_votes = []
    for i, vote in enumerate(votes):
        ct = encrypt(public_key, vote)
        encrypted_votes.append(ct)
        print(f"   Voter {i}: vote={vote} → cipher={str(ct)[:30]}...")

    # Demonstrate semantic security: same value, different ciphertext
    print("\n🔐 Semantic security check:")
    e1 = encrypt(public_key, 1)
    e2 = encrypt(public_key, 1)
    print(f"   E(1) = {str(e1)[:30]}...")
    print(f"   E(1) = {str(e2)[:30]}...")
    print(f"   Same ciphertext? {e1 == e2}  (should be False)")

    # Server tallies by multiplying ciphertexts (never sees plaintext!)
    print("\n📦 Server multiplies ciphertexts (homomorphic addition)...")
    tally_cipher = encrypted_votes[0]
    for ct in encrypted_votes[1:]:
        tally_cipher = add_encrypted(public_key, tally_cipher, ct)
    print(f"   Combined cipher = {str(tally_cipher)[:30]}...")

    # Decrypt the tally
    tally = decrypt(private_key, tally_cipher)
    print(f"\n🗳️  Decrypted tally: {tally} yes, {num_voters - tally} no")
    print(f"   Matches actual?  {tally == sum(votes)}")


def multi_candidate_poll():
    """
    Multi-candidate poll using positional encoding.

    Encode vote for candidate i as 10^i. The homomorphic sum gives
    a number whose digits are the per-candidate vote counts.

    e.g., 3 votes for candidate 0, 5 for candidate 1, 2 for candidate 2
          → sum = 3·1 + 5·10 + 2·100 = 253 → digits [3, 5, 2]
    """
    print("\n" + "=" * 60)
    print("ENCRYPTED MULTI-CANDIDATE POLL")
    print("=" * 60)

    num_candidates = 3
    num_voters = 15
    base = 100  # supports up to 99 votes per candidate

    print(f"\n🔑 Generating keys...")
    public_key, private_key = generate_keys(bits=512)

    # Simulate votes
    votes = [random.randrange(num_candidates) for _ in range(num_voters)]
    actual_counts = [votes.count(i) for i in range(num_candidates)]
    print(f"\n📊 {num_voters} voters, {num_candidates} candidates:")
    print(f"   Votes:  {votes}")
    print(f"   Actual: {['Candidate ' + str(i) + ': ' + str(c) for i, c in enumerate(actual_counts)]}")

    # Encode and encrypt
    print("\n🔒 Encoding and encrypting...")
    encrypted_votes = []
    for vote in votes:
        encoded = base ** vote  # positional encoding
        ct = encrypt(public_key, encoded)
        encrypted_votes.append(ct)

    # Homomorphic tally
    print("📦 Server computes homomorphic sum...")
    tally_cipher = encrypted_votes[0]
    for ct in encrypted_votes[1:]:
        tally_cipher = add_encrypted(public_key, tally_cipher, ct)

    # Decrypt and decode
    tally_encoded = decrypt(private_key, tally_cipher)
    decoded_counts = []
    remaining = tally_encoded
    for _ in range(num_candidates):
        decoded_counts.append(remaining % base)
        remaining //= base

    print(f"\n🗳️  Decrypted results:")
    for i, count in enumerate(decoded_counts):
        bar = "█" * count
        print(f"   Candidate {i}: {count} votes  {bar}")
    print(f"   Matches actual? {decoded_counts == actual_counts}")


if __name__ == "__main__":
    yes_no_poll()
    multi_candidate_poll()
