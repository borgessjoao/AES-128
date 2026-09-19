# testes galois.py
from src.galois import xtime, multiply

def test_galois_xtime():
    assert xtime(0x87) == 0x15
    assert xtime(0x57) == 0xAE

def test_galois_multiply():
    assert multiply(0x57, 0x03) == 0xF9
    assert multiply(0x57, 0x13) == 0xFE
    assert multiply(0x02, 0x87) == 0x15 # comutatividade
    assert multiply(0x87, 0x02) == 0x15

# testes sbox.py
from src.sbox import SBOX, INV_SBOX, RCON

def test_sbox_mapping():
    """Valida mapeamentos conhecidos da SBOX."""
    assert SBOX[0x00] == 0x63
    assert INV_SBOX[0x63] == 0x00

def test_sbox_symmetry():
    """Garante que a INV_SBOX é a exata inversa da SBOX para todos os bytes."""
    for byte in range(256):
        cifrado = SBOX[byte]
        decifrado = INV_SBOX[cifrado]
        assert byte == decifrado

def test_rcon():
    """Valida as constantes de rodada do AES."""
    # Como a lista começa direto em 0x01, a rodada 1 usa índice 0
    assert RCON[0] == 0x01
    # A rodada 10 usa o índice 9
    assert RCON[9] == 0x36

# testes key_expansion.py
from src.key_expansion import rot_word, sub_word, expand_key

def test_key_expansion_utils():
    """Valida as funções auxiliares de rotação e substituição."""
    assert rot_word([0x01, 0x02, 0x03, 0x04]) == [0x02, 0x03, 0x04, 0x01]
    # Usando o início da SBOX: SBOX[0]=0x63, SBOX[1]=0x7C, SBOX[2]=0x77, SBOX[3]=0x7B
    assert sub_word([0x00, 0x01, 0x02, 0x03]) == [0x63, 0x7C, 0x77, 0x7B]

def test_nist_key_expansion():
    """
    Valida a expansão completa usando o vetor oficial do padrão AES (NIST FIPS-197, Apêndice A).
    Chave original: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
    """
    nist_key = bytes([
        0x2b, 0x7e, 0x15, 0x16, 
        0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88, 
        0x09, 0xcf, 0x4f, 0x3c
    ])
    
    round_keys = expand_key(nist_key)
    
    # Validação 1: O AES-128 deve gerar 11 matrizes (rodadas 0 a 10)
    assert len(round_keys) == 11
    
    # Validação 2: A rodada 0 (primeira matriz) deve ser exatamente a chave original
    # round_keys[0] representa a chave original. Coluna 0 deve ser os 4 primeiros bytes.
    assert round_keys[0][0][0] == 0x2b # Linha 0, Coluna 0
    assert round_keys[0][1][0] == 0x7e # Linha 1, Coluna 0
    assert round_keys[0][2][0] == 0x15 # Linha 2, Coluna 0
    assert round_keys[0][3][0] == 0x16 # Linha 3, Coluna 0
    
    # Validação 3: Primeira palavra (coluna 0) da Rodada 1 deve ser [0xa0, 0xfa, 0xfe, 0x17]
    assert round_keys[1][0][0] == 0xa0
    assert round_keys[1][1][0] == 0xfa
    assert round_keys[1][2][0] == 0xfe
    assert round_keys[1][3][0] == 0x17

# testes funções sub_bytes, inv_shift_rows e mix_columns de aes.py
from src.aes import sub_bytes, inv_shift_rows, mix_columns, MIXER_MATRIX, INV_MIXER_MATRIX
from src.sbox import INV_SBOX

def test_generic_sub_bytes():
    """Valida a substituição in-place genérica passando a INV_SBOX."""
    state = [
        [0x63, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00]
    ]
    # SBOX[0x00] == 0x63, logo INV_SBOX[0x63] deve ser 0x00.
    # O elemento 0,0 deve virar 0x00 e os outros 0x52 (pois INV_SBOX[0x00] == 0x52).
    sub_bytes(state, INV_SBOX)
    
    assert state[0][0] == 0x00
    assert state[0][1] == 0x52
    assert state[1][0] == 0x52

def test_inv_shift_rows():
    """Valida a rotação correta das linhas para a direita."""
    state = [
        [0, 1, 2, 3],
        [4, 5, 6, 7],
        [8, 9, 10, 11],
        [12, 13, 14, 15]
    ]
    inv_shift_rows(state)
    
    assert state[0] == [0, 1, 2, 3]         # Intacta
    assert state[1] == [7, 4, 5, 6]         # 1 pra direita
    assert state[2] == [10, 11, 8, 9]       # 2 pra direita
    assert state[3] == [13, 14, 15, 12]     # 3 pra direita

def test_mix_columns_symmetry():
    """
    Requisito Crítico: Valida a generalização do mix_columns. 
    Aplicar MIXER_MATRIX e depois INV_MIXER_MATRIX deve restaurar o bloco.
    """
    original_state = [
        [0x87, 0xF2, 0x4D, 0x97],
        [0x6E, 0x4C, 0x90, 0xEC],
        [0x46, 0xE7, 0x4A, 0xC3],
        [0xA6, 0x8C, 0xD8, 0x95]
    ]
    state = [row[:] for row in original_state]
    
    # Cifragem
    mix_columns(state, MIXER_MATRIX)
    # Decifragem
    mix_columns(state, INV_MIXER_MATRIX)
    
    assert state == original_state