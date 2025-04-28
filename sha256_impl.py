#!/usr/bin/env python3

def sha256(message):
    """
    Implementasi SHA-256 dari awal tanpa menggunakan hashlib
    """
    # Konstanta (delapan kata pertama bagian pecahan dari akar kuadrat dari 8 prima pertama 2..19)
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # 64 konstanta (bagian pecahan dari akar kubik dari 64 prima pertama 2..311)
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Fungsi pembantu
    def right_rotate(value, amount):
        return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF

    # Pra-pemrosesan
    message_bytes = message if isinstance(message, bytes) else message.encode()
    
    # Padding pesan sesuai dengan spesifikasi SHA-256
    message_len_bits = len(message_bytes) * 8
    message_bytes += b'\x80'  # Append bit '1' diikuti oleh bit '0'
    
    # Append padding bytes sampai panjang pesan ≡ 448 (mod 512)
    while (len(message_bytes) * 8) % 512 != 448:
        message_bytes += b'\x00'
    
    # Append panjang pesan asli sebagai 64-bit unsigned integer
    message_bytes += message_len_bits.to_bytes(8, byteorder='big')
    
    # Memproses pesan dalam chunk 512-bit (64 bytes)
    for chunk_start in range(0, len(message_bytes), 64):
        chunk = message_bytes[chunk_start:chunk_start+64]
        
        # Memecah chunk menjadi 16 kata 32-bit
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:(i+1)*4], byteorder='big')
        
        # Memperluas 16 kata menjadi 64 kata
        for i in range(16, 64):
            s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
        
        # Inisialisasi variabel kerja dengan nilai hash saat ini
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        
        # Kompresi utama
        for i in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + k[i] + w[i]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        
        # Menambahkan nilai yang dikompresi ke nilai hash saat ini
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF
    
    # Menghasilkan hash akhir (256 bit = 32 byte)
    digest = (h0.to_bytes(4, 'big') + h1.to_bytes(4, 'big') + 
              h2.to_bytes(4, 'big') + h3.to_bytes(4, 'big') + 
              h4.to_bytes(4, 'big') + h5.to_bytes(4, 'big') + 
              h6.to_bytes(4, 'big') + h7.to_bytes(4, 'big'))
    
    return digest

def sha256_hex(message):
    """Mengembalikan representasi hex dari hash SHA-256"""
    return sha256(message).hex()

class SHA256:
    """Kelas untuk mengemulasi hashlib.sha256()"""
    def __init__(self, message=b''):
        self.buffer = message if isinstance(message, bytes) else message.encode()
        self.digest_size = 32  # 256 bits = 32 bytes
        
    def update(self, message):
        message_bytes = message if isinstance(message, bytes) else message.encode()
        self.buffer += message_bytes
        return self
        
    def digest(self):
        return sha256(self.buffer)
        
    def hexdigest(self):
        return sha256_hex(self.buffer)

def new(message=b''):
    """Fungsi untuk membuat objek hash baru, mengemulasi hashlib.sha256()"""
    return SHA256(message)