"""
Módulo para expansão de chave do AES-128 (128 bits -> 11 subchaves de 16 bytes).
"""

def rot_word(word: list[int]) -> list[int]:
    """
    Realiza a rotação circular de 1 byte para a esquerda em uma palavra de 4 bytes.
    Exemplo: [b0, b1, b2, b3] -> [b1, b2, b3, b0].
    
    :param word: Lista de 4 inteiros (bytes).
    :return: Nova lista com os 4 bytes rotacionados.
    """
    pass


def sub_word(word: list[int]) -> list[int]:
    """
    Aplica a substituição da SBOX em cada um dos 4 bytes de uma palavra.
    
    :param word: Lista de 4 inteiros (bytes).
    :return: Nova lista com os bytes substituídos pela SBOX.
    """
    pass


def expand_key(key: bytes) -> list[list[list[int]]]:
    """
    Deriva as 11 subchaves de 128 bits a partir da chave original de 16 bytes.
    
    Gera uma sequência de 44 palavras de 32 bits e as reorganiza em 11
    matrizes de estado 4x4 (uma matriz de subchave para cada round de 0 a 10).
    
    :param key: Chave original de 16 bytes.
    :return: Lista contendo 11 matrizes de subchave (cada uma 4x4).
    """
    pass