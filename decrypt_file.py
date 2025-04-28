#!/usr/bin/env python3
import sys
import rsa
import sha256_impl as sha256

def load_key(path: str):
    """Read "hex_d:hex_n" and return (int_d, int_n)."""
    hex_part, hex_mod = open(path, "r").read().strip().split(":")
    return int(hex_part, 16), int(hex_mod, 16)

def oaep_decode(em: bytes, k: int, label: bytes = b"", hash_func=sha256.SHA256) -> bytes:
    """Inverse of rsa.oaep_encode; returns the original message bytes."""
    hLen = hash_func().digest_size
    if len(em) != k:
        raise ValueError(f"Ciphertext block has wrong length: {len(em)} != {k}")
    # 1. EM = 0x00 || maskedSeed || maskedDB
    if em[0] != 0:
        raise ValueError("Decryption error: leading byte not zero")
    masked_seed = em[1 : 1 + hLen]
    masked_db   = em[1 + hLen : ]
    # 2. seed = maskedSeed ⊕ MGF1(maskedDB, hLen)
    seed_mask = rsa.mgf1(masked_db, hLen, hash_func=hash_func)
    seed      = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))
    # 3. db = maskedDB ⊕ MGF1(seed, k - hLen - 1)
    db_mask = rsa.mgf1(seed, k - hLen - 1, hash_func=hash_func)
    db      = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    # 4. split DB = l_hash || PS || 0x01 || message
    l_hash, rest = db[:hLen], db[hLen:]
    if l_hash != hash_func(label).digest():
        raise ValueError("Decryption error: lHash mismatch")
    # 5. find the 0x01 separator
    sep_idx = rest.find(b"\x01")
    if sep_idx < 0:
        raise ValueError("Decryption error: 0x01 separator not found")
    return rest[sep_idx+1 :]

def decrypt_file(in_path: str, out_path: str, privkey_path: str):
    d, n = load_key(privkey_path)
    k = (n.bit_length() + 7) // 8

    with open(in_path, "rb") as f_in, open(out_path, "wb") as f_out:
        while True:
            chunk = f_in.read(k)
            if not chunk:
                break
            # RSA primitive: m = c^d mod n
            m_int = pow(int.from_bytes(chunk, "big"), d, n)
            em    = m_int.to_bytes(k, "big")
            # OAEP-decode to get back the original bytes
            plain_block = oaep_decode(em, k, hash_func=sha256.SHA256)
            f_out.write(plain_block)

# --- CLI entry point ---
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python decrypt_file.py <infile> <outfile> <privkey>")
        sys.exit(1)
    _, infile, outfile, privkey = sys.argv
    decrypt_file(infile, outfile, privkey)
    print(f"Decrypted {infile} → {outfile}")