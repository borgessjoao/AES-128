"""
Conjunto completo de testes automatizados para a validação do AES-128.
Inclui testes unitários por camada e testes de integração com vetores oficiais do NIST FIPS-197.
"""
import pytest

# ---------------------------------------------------------------------------
# 1. Testes de Galois (src/galois.py)
# ---------------------------------------------------------------------------
from src.galois import xtime, multiply

def test_galois_xtime():
    assert xtime(0x87) == 0x15
    assert xtime(0x57) == 0xAE

def test_galois_multiply():
    assert multiply(0x57, 0x03) == 0xF9
    assert multiply(0x57, 0x13) == 0xFE
    assert multiply(0x02, 0x87) == 0x15
    assert multiply(0x87, 0x02) == 0x15  # Comutatividade


# ---------------------------------------------------------------------------
# 2. Testes de S-Box e Constantes (src/sbox.py)
# ---------------------------------------------------------------------------
from src.sbox import SBOX, INV_SBOX, RCON

def test_sbox_mapping():
    assert SBOX[0x00] == 0x63
    assert INV_SBOX[0x63] == 0x00

def test_sbox_symmetry():
    for byte in range(256):
        cifrado = SBOX[byte]
        decifrado = INV_SBOX[cifrado]
        assert byte == decifrado

def test_rcon():
    assert RCON[0] == 0x01
    assert RCON[9] == 0x36


# ---------------------------------------------------------------------------
# 3. Testes de Expansão de Chave (src/key_expansion.py)
# ---------------------------------------------------------------------------
from src.key_expansion import rot_word, sub_word, expand_key

def test_key_expansion_utils():
    assert rot_word([0x01, 0x02, 0x03, 0x04]) == [0x02, 0x03, 0x04, 0x01]
    assert sub_word([0x00, 0x01, 0x02, 0x03]) == [0x63, 0x7C, 0x77, 0x7B]

def test_nist_key_expansion():
    nist_key = bytes([
        0x2B, 0x7E, 0x15, 0x16, 
        0x28, 0xAE, 0xD2, 0xA6, 
        0xAB, 0xF7, 0x15, 0x88, 
        0x09, 0xCF, 0x4F, 0x3C
    ])
    round_keys = expand_key(nist_key)
    
    assert len(round_keys) == 11
    # Round 0 (chave original)
    assert round_keys[0][0][0] == 0x2B
    assert round_keys[0][1][0] == 0x7E
    assert round_keys[0][2][0] == 0x15
    assert round_keys[0][3][0] == 0x16
    # Round 1 (primeira coluna)
    assert round_keys[1][0][0] == 0xA0
    assert round_keys[1][1][0] == 0xFA
    assert round_keys[1][2][0] == 0xFE
    assert round_keys[1][3][0] == 0x17


# ---------------------------------------------------------------------------
# 4. Testes de Transformações do AES (src/aes.py)
# ---------------------------------------------------------------------------
from src.aes import (
    bytes_to_matrix,
    matrix_to_bytes,
    sub_bytes,
    shift_rows,
    inv_shift_rows,
    mix_columns,
    add_round_key,
    cipher_block,
    inv_cipher_block,
    MIXER_MATRIX,
    INV_MIXER_MATRIX,
)

def test_matrix_bytes_symmetry():
    data = bytes(range(16))
    matrix = bytes_to_matrix(data)
    recovered = matrix_to_bytes(matrix)
    assert recovered == data

def test_sub_bytes_and_inverse():
    original = [[i * 4 + j for j in range(4)] for i in range(4)]
    state = [row[:] for row in original]
    
    sub_bytes(state, SBOX)
    assert state != original
    sub_bytes(state, INV_SBOX)
    assert state == original

def test_shift_rows_and_inverse():
    original = [
        [0, 1, 2, 3],
        [4, 5, 6, 7],
        [8, 9, 10, 11],
        [12, 13, 14, 15]
    ]
    state = [row[:] for row in original]
    
    # Cifragem (desloca para esquerda)
    shift_rows(state)
    assert state[0] == [0, 1, 2, 3]
    assert state[1] == [5, 6, 7, 4]
    assert state[2] == [10, 11, 8, 9]
    assert state[3] == [15, 12, 13, 14]
    
    # Decifragem (desloca para direita)
    inv_shift_rows(state)
    assert state == original

def test_mix_columns_symmetry():
    original = [
        [0x87, 0xF2, 0x4D, 0x97],
        [0x6E, 0x4C, 0x90, 0xEC],
        [0x46, 0xE7, 0x4A, 0xC3],
        [0xA6, 0x8C, 0xD8, 0x95]
    ]
    state = [row[:] for row in original]
    mix_columns(state, MIXER_MATRIX)
    mix_columns(state, INV_MIXER_MATRIX)
    assert state == original

def test_add_round_key_involutive():
    state = bytes_to_matrix(bytes(range(16)))
    key = bytes_to_matrix(bytes([0xAA] * 16))
    original = [row[:] for row in state]
    
    # APLICAR XOR DUAS VEZES RESTAURA O ESTADO
    add_round_key(state, key)
    assert state != original
    add_round_key(state, key)
    assert state == original


# ---------------------------------------------------------------------------
# 5. Vetor de Teste Oficial NIST FIPS-197 (Cifragem e Decifragem Completa)
# ---------------------------------------------------------------------------
def test_nist_fips_197_full_block():
    """
    Vetor canônico do Apêndice B do NIST FIPS-197.
    Plaintext:  32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
    Key:        2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
    Ciphertext: 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
    """
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected_ciphertext = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    
    round_keys = expand_key(key)
    
    # Cifragem
    ciphertext = cipher_block(plaintext, round_keys)
    assert ciphertext == expected_ciphertext
    
    # Decifragem
    decrypted = inv_cipher_block(ciphertext, round_keys)
    assert decrypted == plaintext


# ---------------------------------------------------------------------------
# 6. Testes de Padding PKCS#7 (src/padding.py)
# ---------------------------------------------------------------------------
from src.padding import pad, unpad

def test_pkcs7_padding():
    data = b"Vasco da Gama"  # 13 bytes -> faltam 3 bytes de 0x03
    padded = pad(data)
    assert len(padded) == 16
    assert padded[-3:] == b"\x03\x03\x03"
    assert unpad(padded) == data

def test_pkcs7_exact_block():
    data = b"0123456789ABCDEF"  # 16 bytes exatos -> adiciona bloco inteiro com 0x10
    padded = pad(data)
    assert len(padded) == 32
    assert padded[-16:] == b"\x10" * 16
    assert unpad(padded) == data


# ---------------------------------------------------------------------------
# 7. Testes de Utilitários CLI (src/utils.py)
# ---------------------------------------------------------------------------
from src.utils import parse_key, parse_ciphertext, format_ciphertext

def test_parse_key():
    # Chave string (16 caracteres)
    assert parse_key("minhachave123456", is_hex=False) == b"minhachave123456"
    # Chave hex (32 caracteres)
    assert parse_key("2b7e151628aed2a6abf7158809cf4f3c", is_hex=True) == bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

def test_format_and_parse_ciphertext():
    # 16 bytes completos para satisfazer a validação de tamanho de bloco do AES
    raw_cipher = bytes(range(16))

    # Formato Hexadecimal
    hex_str = format_ciphertext(raw_cipher, to_decimal=False)
    assert hex_str == "000102030405060708090a0b0c0d0e0f"
    assert parse_ciphertext(hex_str, is_decimal=False) == raw_cipher

    # Formato Lista Decimal
    dec_str = format_ciphertext(raw_cipher, to_decimal=True)
    assert dec_str == "[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]"
    assert parse_ciphertext(dec_str, is_decimal=True) == raw_cipher