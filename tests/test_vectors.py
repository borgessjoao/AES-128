from src.galois import xtime, multiply

def test_galois_xtime():
    assert xtime(0x87) == 0x15
    assert xtime(0x57) == 0xAE

def test_galois_multiply():
    assert multiply(0x57, 0x03) == 0xF9
    assert multiply(0x57, 0x13) == 0xFE
    assert multiply(0x02, 0x87) == 0x15 # comutatividade
    assert multiply(0x87, 0x02) == 0x15

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