"""
ECC Digital Signature (ECDSA) - implemented from scratch.

Curve:  y^2 = x^3 + a*x + b  over Z_p        (NIST P-256)
Follows the course notes: Figure 2 (point addition rule),
Figure 6 (key generation, signing, verification).

Usage:
    python main.py                                          (demo)
    python main.py keygen
    python main.py sign   --key <d-hex>  --msg "hello"
    python main.py verify --pub <Q-hex>  --msg "hello" --sig <sig-hex>
"""

import argparse
import hashlib
import secrets
import sys

# --- Curve parameters: NIST P-256 -------------------------------------------
p  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
n  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G  = (Gx, Gy)

# The point at infinity O is represented by None.


# --- Figure 2: the addition rule --------------------------------------------
def point_add(P, Q):
    if P is None:                        # rule 1: O + Q = Q
        return Q
    if Q is None:                        # rule 1: P + O = P
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:  # rule 2: P + (-P) = O
        return None

    if P == Q:                           # tangent:  lam = (3x1^2 + a) / 2y1
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:                                # secant:   lam = (y2 - y1) / (x2 - x1)
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mul(k, P):
    """k*P by double-and-add."""
    result = None
    while k > 0:
        if k & 1:
            result = point_add(result, P)
        P = point_add(P, P)
        k >>= 1
    return result


def on_curve(P):
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0


def hash_message(msg):
    """h(m) as an integer."""
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")


# --- Figure 6(a): key generation --------------------------------------------
def generate_keys():
    d = secrets.randbelow(n - 2) + 1     # private key, 1 <= d <= n-1
    Q = scalar_mul(d, G)                 # public key  Q = d*G
    return d, Q


# --- Figure 6(b): signature generation --------------------------------------
def sign(d, msg):
    z = hash_message(msg)
    while True:
        k = secrets.randbelow(n - 2) + 1     # random per-message nonce
        x1, _ = scalar_mul(k, G)             # k*G
        r = x1 % n
        if r == 0:
            continue
        s = pow(k, -1, n) * (z + d * r) % n  # s = k^-1 (h(m) + d*r) mod n
        if s == 0:
            continue
        return (r, s)


# --- Figure 6(c): signature verification ------------------------------------
def verify(Q, msg, signature):
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False

    z = hash_message(msg)
    w = pow(s, -1, n)                    # w = s^-1 mod n
    u1 = z * w % n
    u2 = r * w % n

    X = point_add(scalar_mul(u1, G), scalar_mul(u2, Q))
    if X is None:
        return False
    return X[0] % n == r                 # accept iff v == r


# --- Hex helpers so keys and signatures can be passed on the command line ---
def key_to_hex(Q):
    return f"{Q[0]:064x}{Q[1]:064x}"


def key_from_hex(text):
    Q = (int(text[:64], 16), int(text[64:], 16))
    if len(text) != 128 or not on_curve(Q):
        raise ValueError("invalid public key")
    return Q


def sig_to_hex(signature):
    return f"{signature[0]:064x}{signature[1]:064x}"


def sig_from_hex(text):
    if len(text) != 128:
        raise ValueError("invalid signature")
    return (int(text[:64], 16), int(text[64:], 16))


# --- Demo -------------------------------------------------------------------
def demo():
    message = b"This document was signed with ECC."

    d, Q = generate_keys()
    print("Curve      : NIST P-256  (y^2 = x^3 + ax + b mod p)")
    print("Message    :", message.decode())
    print()
    print("Private key d :", f"{d:064x}")
    print("Public key  Q :", key_to_hex(Q))
    print()

    signature = sign(d, message)
    print("Signature r :", f"{signature[0]:064x}")
    print("Signature s :", f"{signature[1]:064x}")
    print()

    print("Verify original message :", verify(Q, message, signature))
    print("Verify altered message  :", verify(Q, b"This document was altered!", signature))


# --- Command line -----------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="ECC digital signature (ECDSA)")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("keygen", help="generate a key pair")

    p_sign = sub.add_parser("sign", help="sign a message")
    p_sign.add_argument("--key", required=True, help="private key in hex")
    p_sign.add_argument("--msg", required=True, help="message to sign")

    p_verify = sub.add_parser("verify", help="verify a signature")
    p_verify.add_argument("--pub", required=True, help="public key in hex")
    p_verify.add_argument("--msg", required=True, help="the signed message")
    p_verify.add_argument("--sig", required=True, help="signature in hex")

    args = parser.parse_args()

    if args.command is None:
        demo()

    elif args.command == "keygen":
        d, Q = generate_keys()
        print("private key:", f"{d:064x}")
        print("public key :", key_to_hex(Q))

    elif args.command == "sign":
        d = int(args.key, 16)
        if not 1 <= d < n:
            sys.exit("private key out of range")
        print(sig_to_hex(sign(d, args.msg.encode())))

    elif args.command == "verify":
        Q = key_from_hex(args.pub)
        signature = sig_from_hex(args.sig)
        ok = verify(Q, args.msg.encode(), signature)
        print("VALID" if ok else "INVALID")


if __name__ == "__main__":
    main()