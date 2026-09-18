"""
Módulo para aplicação e remoção de preenchimento segundo a norma PKCS#7.
"""

def pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Adiciona bytes de padding PKCS#7 aos dados até completar um múltiplo do tamanho do bloco.
    
    :param data: Bytes originais da mensagem.
    :param block_size: Tamanho do bloco em bytes (padrão: 16).
    :return: Sequência de bytes alinhada.
    """
    pass


def unpad(data: bytes) -> bytes:
    """
    Valida e remove o preenchimento PKCS#7 da mensagem decifrada.
    Lança ValueError se o preenchimento for inválido.
    
    :param data: Sequência de bytes preenchida.
    :return: Sequência de bytes original sem preenchimento.
    """
    pass