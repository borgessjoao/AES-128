"""
Módulo responsável pelas operações aritméticas sobre o corpo finito GF(2^8)
com o polinômio irredutível m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B).
"""

def xtime(b: int) -> int:
    """
    Multiplica um byte por {02} em GF(2^8).
    
    Aplica deslocamento à esquerda de 1 bit com redução por XOR condicional
    com 0x1B caso ocorra overflow do 8º bit.
    
    :param b: Inteiro representando um byte (0 a 255).
    :return: Resultado da multiplicação em GF(2^8) limitado a 8 bits.
    """
    shifted = b << 1
    if b & 0x80:
        return (shifted ^ 0x1B) & 0xFF
    return shifted & 0xFF


def multiply(a: int, b: int) -> int:
    """
    Multiplicação genérica entre dois elementos em GF(2^8).
    
    Utiliza o algoritmo de multiplicação camponesa (shift-and-add com xtime).
    Essencial para a etapa de MixColumns genérica (cifragem e decifragem).
    
    :param a: Primeiro byte (0 a 255).
    :param b: Segundo byte (0 a 255).
    :return: Produto no corpo finito GF(2^8).
    """
    result = 0
    
    while b > 0:
        if b & 1: 
            result ^= a # Se o bit menos significativo de 'b' for 1, somamos 'a' ao resultado (XOR)
        a = xtime(a)
        b >>= 1 # Desloca 'b' para a direita para processar o próximo bit
            
    return result