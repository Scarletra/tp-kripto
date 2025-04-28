import random
import math
import secrets
import math
import secrets
from typing import Tuple
import hashlib

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

def power_mod(base, exponent, modulus):
    """
    Fungsi untuk menghitung (base^exponent) % modulus
    """
    result = 1
    base = base % modulus
    while exponent > 0:
        # Jika exponent ganjil, kalikan result dengan base
        if exponent & 1:
            result = (result * base) % modulus
        # Di sini, exponent dipastikan genap
        exponent >>= 1  # exponent = exponent / 2
        base = (base * base) % modulus
    return result

def miller_rabin_test(d, n):
    """
    Miller-Rabin primality test
    Returns False if n is composite, True if n is probably prime
    """
    # Ambil angka random dalam range [2..n-2]
    a = 2 + random.randint(1, n - 4)
    
    # Hitung a^d % n
    x = power_mod(a, d, n)
    
    if x == 1 or x == n - 1:
        return True
    
    # x dikuadratkan terus sampai salah satu dari kondisi ini tidak tercapai:
    # (i) d tidak mencapai n-1
    # (ii) (x^2) % n tidak sama dengan 1
    # (iii) (x^2) % n tidak sama dengan n-1
    while d != n - 1:
        x = (x * x) % n
        d *= 2
        
        if x == 1:
            return False
        if x == n - 1:
            return True
    
    return False

def is_prime(n, k=40):
    """
    Cek apakah n prima dengan Miller-Rabin primality test
    k menentukan akurasi tes
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    # Cari r sehingga n = 2^d * r + 1
    d = n - 1
    while d % 2 == 0:
        d //= 2
    
    # Witness loop
    for _ in range(k):
        if not miller_rabin_test(d, n):
            return False
    
    return True

def generate_prime(bits):
    """Generate bilangan prima random dengan panjang bits"""
    while True:
        # Generate bilangan ganjil random dengan panjang 'bits'
        p = secrets.randbits(bits)
        # Tetapkan bit tertinggi untuk memastikan bilangan memiliki panjang bit yang tepat seperti yang ditentukan
        p |= (1 << bits - 1)
        # Pastikan p ganjil
        p |= 1
        
        if is_prime(p):
            return p

def gcd(a, b):
    """Fungsi untuk menghitung FPB dengan algoritma Euclidean"""
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    """Fungsi untuk menghitung KPK"""
    return a * b // gcd(a, b)

def generate_keypair(bits=2048):
    """
    Generate RSA key pair dengan implementasi yang lebih aman
    
    Returns:
    - Tuple berisi public key (e, n) dan private key (d, n)
    """
    print(f"Generating {bits}-bit RSA key pair...")
    print("Generating prime p...")
    p = generate_prime(bits // 2)
    print("Generating prime q...")
    q = generate_prime(bits // 2)
    
    # Pastikan p dan q tidak terlalu dekat
    while abs(p - q) < 2**(bits // 2 - 100):
        q = generate_prime(bits // 2)
    
    # Hitung n = p * q
    n = p * q
    
    # Hitung fungsi totient Carmichael λ(n) = lcm(p-1, q-1)
    lambda_n = lcm(p - 1, q - 1)
    
    # Pilih e sehingga 1 < e < λ(n) dan gcd(e, λ(n)) = 1
    # Umumnya 65537 (2^16 + 1)
    e = 65537
    
    # Pastikan e dan λ(n) relatif prima
    if gcd(e, lambda_n) != 1:
        raise Exception("e and λ(n) are not coprime")
    
    # Hitung d sehingga d*e ≡ 1 (mod λ(n))
    d = modinv(e, lambda_n)
    
    # Public key: (e, n), Private key: (d, n)
    return ((e, n), (d, n))

def convert_to_hex(key):
    """Konversi key (e/d, n) ke dalam representasi hexadecimal"""
    e_or_d, n = key
    return f"{e_or_d:x}:{n:x}"

def save_to_file(content, filename):
    """Save content to file"""
    with open(filename, 'w') as f:
        f.write(content)
    print(f"Saved to {filename}")

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

def oaep_decode(em: bytes, k: int, label: bytes = b"", hash_func=hashlib.sha256) -> bytes:
    hLen = hash_func().digest_size
    # 1. Split:  EM = 0x00 || maskedSeed || maskedDB
    assert em[0] == 0
    masked_seed = em[1 : 1 + hLen]
    masked_db   = em[1 + hLen : ]
    # 2. seedMask = MGF1(maskedDB, hLen)
    seed_mask = mgf1(masked_db, hLen, hash_func)
    seed      = bytes(x^y for x,y in zip(masked_seed, seed_mask))
    # 3. dbMask = MGF1(seed, k-hLen-1)
    db_mask   = mgf1(seed, k - hLen - 1, hash_func)
    db        = bytes(x^y for x,y in zip(masked_db, db_mask))
    # 4. split DB = l_hash || PS || 0x01 || message
    l_hash, rest = db[:hLen], db[hLen:]
    # 5. verify l_hash == H(label)
    assert l_hash == hash_func(label).digest(), "OAEP decryption error"
    # 6. skip over PS until 0x01
    idx = rest.find(b"\x01")
    return rest[idx+1:]
