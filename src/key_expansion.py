from src.sbox import SBOX, RCON

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
    return word[1:] + word[:1]


def sub_word(word: list[int]) -> list[int]:
    """
    Aplica a substituição da SBOX em cada um dos 4 bytes de uma palavra.
    
    :param word: Lista de 4 inteiros (bytes).
    :return: Nova lista com os bytes substituídos pela SBOX.
    """
    return [SBOX[b] for b in word]


def expand_key(key: bytes) -> list[list[list[int]]]:
    """
    Deriva as 11 subchaves de 128 bits a partir da chave original de 16 bytes.
    
    Gera uma sequência de 44 palavras de 32 bits e as reorganiza em 11
    matrizes de estado 4x4 (uma matriz de subchave para cada round de 0 a 10).
    
    :param key: Chave original de 16 bytes.
    :return: Lista contendo 11 matrizes de subchave (cada uma 4x4).
    """
    if len(key) != 16:
        raise ValueError("A chave do AES-128 deve ter exatamente 16 bytes.")

    words: list[list[int]] = []

    # 1. As primeiras 4 palavras (W0 a W3) são exatamente a chave original.
    # Cada palavra agrupa 4 bytes.
    for i in range(4):
        word = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
        words.append(word)

    # 2. Geração das 40 palavras seguintes (W4 a W43)
    for i in range(4, 44):
        # Pegamos a palavra anterior
        temp = words[i - 1].copy()

        # A cada 4 palavras, aplicamos a transformação complexa
        if i % 4 == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            # Fazemos XOR do primeiro byte com a constante de rodada.
            # Como i começa em 4, (i // 4) - 1 resulta no índice 0 do RCON para a primeira rodada
            rcon_value = RCON[(i // 4) - 1]
            temp[0] ^= rcon_value

        # A nova palavra é o XOR da palavra gerada com a palavra de 4 posições atrás
        new_word = [
            words[i - 4][0] ^ temp[0],
            words[i - 4][1] ^ temp[1],
            words[i - 4][2] ^ temp[2],
            words[i - 4][3] ^ temp[3],
        ]
        words.append(new_word)

    # 3. Formatação nas 11 matrizes 4x4 respeitando o contrato state[linha][coluna]
    # No AES, cada 'palavra' (word) que geramos é uma COLUNA da matriz de estado.
    round_keys: list[list[list[int]]] = []

    for round_idx in range(11):
        # Criamos uma matriz 4x4 vazia para a subchave da rodada
        matrix = [[0] * 4 for _ in range(4)]
        
        for col in range(4):
            word_idx = round_idx * 4 + col
            for row in range(4):
                matrix[row][col] = words[word_idx][row]
                
        round_keys.append(matrix)

    return round_keys