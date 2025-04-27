import math
import hashlib
import typing

Key = typing.Tuple[int, int]

def power(x, y, p):
    res = 1;

    x = x % p;
    while (y > 0):
        if (y & 1):
            res = (res * x) % p;

        y = y >> 1; 
        x = (x * x) % p;

    return res;

def sha1(m: bytes) -> bytes:
    '''SHA-1 hash function'''
    hasher = hashlib.sha1()
    hasher.update(m)
    return hasher.digest()

def os2ip(x: bytes) -> int:
    '''Converts an octet string to a nonnegative integer'''
    return int.from_bytes(x, byteorder='big')

def i2osp(x: int, xlen: int) -> bytes:
    '''Converts a nonnegative integer to an octet string of a specified length'''
    return x.to_bytes(xlen, byteorder='big')

def MGF1(seed: bytes, mlen: int) -> bytes:
    '''MGF1 mask generation function with SHA-1'''
    t = b''
    hlen = 128
    for c in range(0, math.ceil(mlen / hlen)):
        _c = i2osp(c, 4)
        t += sha1(seed + _c)
    return t[:mlen]

def xor(data: bytes, mask: bytes) -> bytes:
    masked = b''
    ldata = len(data)
    lmask = len(mask)
    for i in range(max(ldata, lmask)):
        if i < ldata and i < lmask:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
        elif i < ldata:
            masked += data[i].to_bytes(1, byteorder='big')
        else:
            break
    return masked

def get_key_len(key: Key) -> int:
    _, n = key
    return n.bit_length() // 8

def decrypt(privateKey: Key, C: bytes):
    lHash = sha1(b'')

    hLen = 20

    k = get_key_len(privateKey)
    print(len(C))
    assert len(C) == k

    c = os2ip(C)

    d, n = privateKey

    m = power(c, d, n)
    EM = i2osp(m, k)

    _, maskedSeed, maskedDB = EM[:1], EM[1:1 + hLen], EM[1 + hLen:]

    seedMask = MGF1(maskedDB, hLen)
    seed = xor(maskedSeed, seedMask)
    dbMask = MGF1(seed, k - hLen - 1)
    DB = xor(maskedDB, dbMask)

    _lHash = DB[:hLen]

    assert lHash == _lHash
    i = hLen
    while i < len(DB):
        if DB[i] == 0:
            i += 1
            continue
        elif DB[i] == 1:
            i += 1
            break
        else:
            raise Exception()
    M = DB[i:]
    return M