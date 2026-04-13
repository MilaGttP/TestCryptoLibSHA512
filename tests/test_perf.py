import time
from src.sha_wrapper import sha512_hashlib, sha512_pycryptodome


def test_hashlib_1mb_under_1s():
    data = b"a" * 1_000_000
    start = time.time()
    sha512_hashlib(data)
    assert time.time() - start < 1.0


def test_pycryptodome_1mb_under_1s():
    data = b"a" * 1_000_000
    start = time.time()
    sha512_pycryptodome(data)
    assert time.time() - start < 1.0


def test_hashlib_10mb_under_3s():
    data = b"a" * 10_000_000
    start = time.time()
    sha512_hashlib(data)
    assert time.time() - start < 3.0


def test_pycryptodome_10mb_under_3s():
    data = b"a" * 10_000_000
    start = time.time()
    sha512_pycryptodome(data)
    assert time.time() - start < 3.0


def test_libraries_similar_speed():
    data = b"a" * 5_000_000
    t1 = time.time(); sha512_hashlib(data); t1 = time.time() - t1
    t2 = time.time(); sha512_pycryptodome(data); t2 = time.time() - t2
    assert max(t1, t2) / min(t1, t2) < 10
