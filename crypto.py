from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3413 import ctr
from hashlib import pbkdf2_hmac
import os

BLOCK_SIZE = 16

def derive_key(password: str, salt: bytes) -> bytes:
    return pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

def encrypt_file(in_file, out_file, password):
    salt = os.urandom(16)
    iv = os.urandom(8)  # ← ВАЖНО: 8 байт!

    key = derive_key(password, salt)
    cipher = GOST3412Kuznechik(key)

    with open(in_file, 'rb') as f:
        data = f.read()

    encrypted = ctr(cipher.encrypt, BLOCK_SIZE, data, iv)

    with open(out_file, 'wb') as f:
        f.write(salt + iv + encrypted)

def decrypt_file(in_file, out_file, password):
    with open(in_file, 'rb') as f:
        raw = f.read()

    salt = raw[:16]
    iv = raw[16:24]   # ← 8 байт
    data = raw[24:]

    key = derive_key(password, salt)
    cipher = GOST3412Kuznechik(key)

    decrypted = ctr(cipher.encrypt, BLOCK_SIZE, data, iv)

    with open(out_file, 'wb') as f:
        f.write(decrypted)