#!/usr/bin/env python3
import hashlib
import rsa
import sys

# --- your helper functions here ---
def load_key(path: str):
    hex_part, hex_mod = open(path).read().strip().split(":")
    return int(hex_part, 16), int(hex_mod, 16)

def chunk_data(data: bytes, k: int):
    hLen = hashlib.sha256().digest_size
    m_max = k - 2*hLen - 2
    for i in range(0, len(data), m_max):
        yield data[i : i + m_max]

def encrypt_file(in_path: str, out_path: str, pubkey_path: str):
    e, n = load_key(pubkey_path)
    k = (n.bit_length() + 7) // 8
    with open(in_path, "rb") as f_in, open(out_path, "wb") as f_out:
        for block in chunk_data(f_in.read(), k):
            em = rsa.oaep_encode(block, k, hash_func=hashlib.sha256)
            c_int = pow(int.from_bytes(em, "big"), e, n)
            f_out.write(c_int.to_bytes(k, "big"))

# --- CLI entry point ---
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python encrypt_file.py <infile> <outfile> <pubkey>")
        sys.exit(1)
    _, infile, outfile, pubkey = sys.argv
    encrypt_file(infile, outfile, pubkey)
    print(f"Encrypted {infile} → {outfile}")
