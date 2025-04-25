import hashlib
import random
from typing import Tuple

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

def modinv(a: int, m: int) -> int:
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_keys(bits: int = 512) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    def is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                return False
        return True

    def get_prime(bits):
        while True:
            p = random.getrandbits(bits)
            if is_prime(p):
                return p

    p = get_prime(bits)
    q = get_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    return (e, n), (d, n)

def mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
    output = b""
    for counter in range(0, (length + hash_func().digest_size - 1) // hash_func().digest_size):
        c = counter.to_bytes(4, byteorder='big')
        output += hash_func(seed + c).digest()
    return output[:length]

def oaep_encode(message: bytes, k: int, label: bytes = b"", hash_func=hashlib.sha256) -> bytes:
    h_len = hash_func().digest_size
    m_len = len(message)
    if m_len > k - 2 * h_len - 2:
        raise ValueError("Message too long")

    l_hash = hash_func(label).digest()
    ps = b"\x00" * (k - m_len - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message
    seed = random.randbytes(h_len)
    db_mask = mgf1(seed, k - h_len - 1, hash_func)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed_mask = mgf1(masked_db, h_len, hash_func)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db

def encrypt_oaep(message: str, public_key: Tuple[int, int]) -> int:
    message_bytes = message.encode()
    e, n = public_key
    k = (n.bit_length() + 7) // 8
    em = oaep_encode(message_bytes, k)
    m_int = int.from_bytes(em, byteorder='big')
    c = pow(m_int, e, n)
    return c
