"""
Tabelas constantes de substituição não linear e constantes de rodada do padrão AES.
"""

# Matriz 16x16 / vetor de 256 bytes para a etapa SubBytes
SBOX: list[int] = [
    # 0x00 .. 0xFF
]

# Matriz inversa de substituição usada na etapa InvSubBytes
INV_SBOX: list[int] = [
    # 0x00 .. 0xFF
]

# Constantes de rodada (Rcon) para as 10 rodadas do AES-128
RCON: list[int] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]