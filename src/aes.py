"""
Núcleo algorítmico do AES-128 contendo as transformações sobre a matriz de estado
e a orquestração dos rounds de cifragem e decifragem.
"""

from src.sbox import INV_SBOX
from src.galois import multiply

# Matriz de mistura direta para a cifragem
MIXER_MATRIX: list[list[int]] = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02],
]

# Matriz inversa de mistura para a decifragem
INV_MIXER_MATRIX: list[list[int]] = [
    [0x0E, 0x0B, 0x0D, 0x09],
    [0x09, 0x0E, 0x0B, 0x0D],
    [0x0D, 0x09, 0x0E, 0x0B],
    [0x0B, 0x0D, 0x09, 0x0E],
]


def bytes_to_matrix(data: bytes) -> list[list[int]]:
    """
    Converte uma sequência de 16 bytes em uma matriz de estado 4x4 organizada por colunas.
    
    :param data: Bloco de 16 bytes.
    :return: Matriz 4x4 de inteiros.
    """
    pass


def matrix_to_bytes(state: list[list[int]]) -> bytes:
    """
    Converte a matriz de estado 4x4 de volta para uma sequência linear de 16 bytes lida por colunas.
    
    :param state: Matriz 4x4 de inteiros.
    :return: Sequência de 16 bytes.
    """
    pass


def sub_bytes(state: list[list[int]], sbox: list[int]) -> None:
    """
    Aplica a substituição de bytes na matriz de estado utilizando uma tabela SBOX fornecida.
    Modifica a matriz in-place.
    
    :param state: Matriz 4x4 de inteiros.
    :param sbox: Tabela de 256 bytes (direta ou inversa).
    """
    for row in range(4):
        for col in range(4):
            state[row][col] = sbox[state[row][col]]


def shift_rows(state: list[list[int]]) -> None:
    """
    Desloca circularmente as linhas da matriz de estado para a esquerda.
    Modifica a matriz in-place.
    
    :param state: Matriz 4x4 de inteiros.
    """
    pass


def inv_shift_rows(state: list[list[int]]) -> None:
    """
    Desloca circularmente as linhas da matriz de estado para a direita (inverso).
    Modifica a matriz in-place.
    
    :param state: Matriz 4x4 de inteiros.
    """
    # Linha 0 fica intacta
    # Linha 1: Move 1 para a direita
    state[1] = state[1][-1:] + state[1][:-1]
    # Linha 2: Move 2 para a direita
    state[2] = state[2][-2:] + state[2][:-2]
    # Linha 3: Move 3 para a direita
    state[3] = state[3][-3:] + state[3][:-3]


def mix_columns(state: list[list[int]], matrix: list[list[int]]) -> None:
    """
    Executa a mistura de colunas genérica multiplicando o estado por uma matriz 4x4 constante em GF(2^8).
    Atende tanto à cifragem quanto à decifragem variando a matriz passada.
    Modifica a matriz in-place.
    
    :param state: Matriz 4x4 de inteiros (estado).
    :param matrix: Matriz constante 4x4 em GF(2^8) (MIXER_MATRIX ou INV_MIXER_MATRIX).
    """
    for col in range(4):
        # Faz uma cópia da coluna para não usar resultados parciais nas multiplicações subsequentes
        c_copy = [state[0][col], state[1][col], state[2][col], state[3][col]]
        
        for row in range(4):
            # O XOR final das 4 multiplicações na GF(2^8)
            state[row][col] = (
                multiply(matrix[row][0], c_copy[0]) ^
                multiply(matrix[row][1], c_copy[1]) ^
                multiply(matrix[row][2], c_copy[2]) ^
                multiply(matrix[row][3], c_copy[3])
            )


def add_round_key(state: list[list[int]], round_key: list[list[int]]) -> None:
    """
    Combina a matriz de estado com a subchave da rodada aplicando XOR elemento a elemento.
    Modifica a matriz in-place.
    
    :param state: Matriz 4x4 de inteiros.
    :param round_key: Matriz 4x4 de inteiros com a subchave da rodada.
    """
    pass


def cipher_block(block: bytes, round_keys: list[list[list[int]]]) -> bytes:
    """
    Cifra um único bloco de 16 bytes executando os 10 rounds do AES-128.
    
    :param block: Bloco de 16 bytes de texto claro.
    :param round_keys: As 11 subchaves de 128 bits derivadas.
    :return: Bloco de 16 bytes cifrado.
    """
    pass


def inv_cipher_block(block: bytes, round_keys: list[list[list[int]]]) -> bytes:
    """
    Decifra um único bloco de 16 bytes executando o fluxo reverso dos 10 rounds.
    
    :param block: Bloco de 16 bytes cifrado.
    :param round_keys: As 11 subchaves de 128 bits derivadas.
    :return: Bloco de 16 bytes restaurado.
    """
    # 1. Converte a entrada linear para a matriz de estado 4x4
    state = bytes_to_matrix(block)
    
    # 2. AddRoundKey inicial com a última chave da expansão (rodada 10)
    add_round_key(state, round_keys[10])
    
    # 3. Executa as rodadas inversas de 9 até 1
    for i in range(9, 0, -1):
        inv_shift_rows(state)
        sub_bytes(state, INV_SBOX)
        add_round_key(state, round_keys[i])
        mix_columns(state, INV_MIXER_MATRIX)
        
    # 4. Rodada final (rodada 0) - não possui mix_columns
    inv_shift_rows(state)
    sub_bytes(state, INV_SBOX)
    add_round_key(state, round_keys[0])
    
    # 5. Converte o estado de volta para bytes lineares
    return matrix_to_bytes(state)