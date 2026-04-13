import hashlib
from Crypto.Hash import SHA512


def sha512_hashlib(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def sha512_pycryptodome(data: bytes) -> str:
    h = SHA512.new()
    h.update(data)
    return h.hexdigest()
