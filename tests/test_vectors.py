import pytest
from src.sha_wrapper import sha512_hashlib, sha512_pycryptodome

TEST_VECTORS = [
    (
        b"abc",
        "ddaf35a193617abac c417349ae20413112e6fa4e89a97ea2"
        "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f",
    ),
    (
        b"",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc"
        "83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f"
        "63b931bd47417a81a538327af927da3e",
    ),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8"
        "279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca0"
        "31ad85c7a71dd70354ec631238ca3445",
    ),
    (
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa1"
        "7299aeadb6889018501d289e4900f7e4331b99dec4b5433a"
        "c7d329eeb6dd26545e96e55b874be909",
    ),
    (
        b"a" * 1_000_000,
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b204428"
        "5632a803afa973ebde0ff244877ea60a4cb0432ce577c31b"
        "eb009c5c2c49aa2e4eadb217ad8cc09b",
    ),
]


def normalize(digest):
    return digest.replace(" ", "").lower()


# --- hashlib tests ---

@pytest.mark.parametrize("data, expected", TEST_VECTORS)
def test_hashlib_correct(data, expected):
    assert sha512_hashlib(data) == normalize(expected)


def test_hashlib_digest_length():
    assert len(sha512_hashlib(b"abc")) == 128


def test_hashlib_empty_string():
    result = sha512_hashlib(b"")
    assert result == normalize(TEST_VECTORS[1][1])


def test_hashlib_same_input_same_output():
    assert sha512_hashlib(b"test") == sha512_hashlib(b"test")


def test_hashlib_different_inputs_different_output():
    assert sha512_hashlib(b"abc") != sha512_hashlib(b"abd")


# --- pycryptodome tests ---

@pytest.mark.parametrize("data, expected", TEST_VECTORS)
def test_pycryptodome_correct(data, expected):
    assert sha512_pycryptodome(data) == normalize(expected)


def test_pycryptodome_digest_length():
    assert len(sha512_pycryptodome(b"abc")) == 128


def test_pycryptodome_empty_string():
    result = sha512_pycryptodome(b"")
    assert result == normalize(TEST_VECTORS[1][1])


def test_pycryptodome_same_input_same_output():
    assert sha512_pycryptodome(b"test") == sha512_pycryptodome(b"test")


def test_pycryptodome_different_inputs_different_output():
    assert sha512_pycryptodome(b"abc") != sha512_pycryptodome(b"abd")


# --- cross-library consistency ---

@pytest.mark.parametrize("data, expected", TEST_VECTORS)
def test_both_libraries_agree(data, expected):
    assert sha512_hashlib(data) == sha512_pycryptodome(data)


def test_output_is_hex_string():
    result = sha512_hashlib(b"abc")
    assert isinstance(result, str)
    assert all(c in "0123456789abcdef" for c in result)


def test_single_null_byte_not_equal_to_empty():
    assert sha512_hashlib(b"\x00") != sha512_hashlib(b"")
    assert sha512_pycryptodome(b"\x00") != sha512_pycryptodome(b"")
