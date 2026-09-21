# ECC Digital Signature (ECDSA)

An implementation of the Elliptic Curve Digital Signature Algorithm written from
scratch in Python, with no cryptographic libraries. The elliptic curve group
arithmetic, key generation, signing and verification are all implemented
directly from the algorithm definitions.

Curve: **NIST P-256** (also known as secp256r1 / prime256v1)
Hash: **SHA-256**

---

## Requirements

Python 3.8 or newer. Nothing to install — the code uses only the standard
library (`hashlib`, `secrets`, `argparse`).

Python 3.8 is the minimum because the modular inverse is computed with
`pow(x, -1, m)`, which was introduced in that version.

---

## Quick start

```
python main.py
```

Running the program with no arguments performs a full demonstration: it
generates a key pair, signs a message, verifies the signature, then verifies the
same signature against a modified message.

Example output:

```
Curve      : NIST P-256  (y^2 = x^3 + ax + b mod p)
Message    : This document was signed with ECC.

Private key d : d3357d5eda1ae0a10f3260f1d1a74671c7e598cc9c5ad10047f121b0c1a4d814
Public key  Q : 67f8328c0ce9ae2344bb30b8f3e8bb678c1ec768fbc4ab96142a5203aba45c6d
                6ab22b83668161d4c9aa5f4b51e0b195361f037621644443bef639f4227e1210

Signature r : 38ebf8754cec638b0e355fd87030e56c628559ba174d7e7c80d314b10c328779
Signature s : 701308b55b7fce6a4017c9ad160e5cadea7ff061e234ac771397dc9064f1fc09

Verify original message : True
Verify altered message  : False
```

The final two lines are the point of the program: the signature is accepted for
the message that was signed, and rejected for anything else.

---

## Command line usage

### Generate a key pair

```
python main.py keygen
```

Outputs a private key (64 hex characters) and a public key (128 hex characters,
the x and y coordinates of the point Q concatenated). The private key must be
kept secret; the public key is what a verifier needs.

### Sign a message

```
python main.py sign --key <private-key-hex> --msg "Pay 500 EUR to Bob"
```

Outputs the signature as 128 hex characters: the value r followed by the
value s, 32 bytes each.

### Verify a signature

```
python main.py verify --pub <public-key-hex> --msg "Pay 500 EUR to Bob" --sig <signature-hex>
```

Prints `VALID` or `INVALID`, and exits with status 0 or 1 respectively so it can
be used in scripts.

Changing a single character of the message invalidates the signature.

Note that signing the same message twice produces two different signatures, both
valid. This is expected: each signature uses a fresh random nonce k.


---

## How it works

### Curve arithmetic

An elliptic curve over a prime field is the set of points satisfying

```
y^2 = x^3 + a*x + b   (mod p)
```

together with a special element O, the point at infinity, which acts as the
identity. In the code O is represented by `None`.

`point_add(P, Q)` implements the group operation and handles four cases:

1. Either operand is O, in which case the other is returned.
2. Q is the negative of P (same x, opposite y), giving O.
3. P equals Q, where the slope comes from the tangent line,
   `lam = (3*x1^2 + a) / (2*y1)`.
4. The general case, where the slope comes from the secant line,
   `lam = (y2 - y1) / (x2 - x1)`.

In the last two cases the result is
`x3 = lam^2 - x1 - x2` and `y3 = lam*(x1 - x3) - y1`.

Division is modular: `pow(x, -1, p)` computes the multiplicative inverse
of x modulo p, which exists because p is prime.

`scalar_mul(k, P)` computes k*P using double-and-add, reducing roughly 2^256
additions to about 256. Computing Q = d*G is fast, while recovering d from Q is
the elliptic curve discrete logarithm problem and is believed to be
intractable — this asymmetry is the basis of the scheme's security.

### Key generation

Choose a random private key d in the range [1, n-1] and compute the public key
Q = d*G, where G is the standard base point and n is its order. Randomness comes
from the `secrets` module, which is cryptographically secure; `random` would not
be, as its output is predictable.

### Signing

Given a message m and private key d:

1. Compute z = SHA-256(m) as an integer.
2. Choose a random nonce k in [1, n-1].
3. Compute the point k*G = (x1, y1) and set r = x1 mod n. If r = 0, restart.
4. Compute s = k^-1 * (z + d*r) mod n. If s = 0, restart.
5. The signature is the pair (r, s).

The two restart conditions are security requirements. If r = 0 the private key
drops out of the equation for s, and the resulting signature would verify for
any key. If s = 0 then s^-1 does not exist and verification is impossible.

### Verification

Given a message m, public key Q and signature (r, s):

1. Check that r and s both lie in [1, n-1].
2. Compute z = SHA-256(m), and w = s^-1 mod n.
3. Compute u1 = z*w mod n and u2 = r*w mod n.
4. Compute the point u1*G + u2*Q = (x0, y0).
5. Accept the signature if and only if x0 mod n equals r.

This works because Q = d*G, so

```
u1*G + u2*Q = (u1 + u2*d)*G
```

and from the signing equation s = k^-1 * (z + d*r) we get k = w*(z + r*d), hence

```
u1 + u2*d = z*w + r*w*d = w*(z + r*d) = k
```

The verifier therefore reconstructs exactly the point k*G that the signer
computed, without ever learning k or d. Its x-coordinate reduced mod n is r, so
the test succeeds. Only someone holding the private key could have produced a
value of s that makes the arithmetic land on that point.
---

## Relationship to the course material

The implementation follows the structure given in the course notes
*Elliptic Curves and Cryptography*:

| Course notes | Implementation |
| --- | --- |
| Equation (1), the curve over Z_p | curve parameters and `point_add` |
| Figure 2, the addition rule | `point_add` |
| Table 1, the multiple aP | `scalar_mul` |
| Figure 6(a), key generation | `generate_keys` |
| Figure 6(b), signature generation | `sign` |
| Figure 6(c), signature verification | `verify` |

Two deliberate deviations:

- **SHA-256 instead of SHA-1.** The notes specify SHA-1, which has been
  considered unsafe for signatures since practical collisions were demonstrated
  in 2017. ECDSA relies on the collision resistance of its hash function.
- **NIST P-256 instead of the small example curve.** The notes use
  y^2 = x^3 + x + 1 over Z_23 so that the arithmetic can be checked by hand.
  P-256 is a standardised curve with cryptographically meaningful parameter
  sizes, which also makes it possible to cross-check against other
  implementations.

The scheme implemented here is a signature scheme: it provides authenticity and
integrity, proving that the holder of the private key approved a specific
message. It does not provide confidentiality. The ElGamal-style elliptic curve
encryption scheme and the Diffie-Hellman key exchange described elsewhere in the
notes are separate constructions and are not implemented here.

---

## References

- Course notes, *Elliptic Curves and Cryptography*
- FIPS 186-4, *Digital Signature Standard*, NIST
- SEC 1, *Elliptic Curve Cryptography*, Certicom Research
- RFC 6979, *Deterministic Usage of DSA and ECDSA*