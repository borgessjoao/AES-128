"""
Módulo para aplicação e remoção de preenchimento segundo a norma PKCS#7.
Garante que mensagens de tamanho arbitrário sejam alinhadas para múltiplos de 16 bytes.
"""


def pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Adiciona preenchimento PKCS#7 aos dados até atingir um múltiplo exato de block_size.
    
    Regra do PKCS#7:
    Se faltam N bytes para completar o bloco, adiciona-se N vezes o byte de valor N.
    Se a mensagem já for múltiplo exato de block_size, adiciona-se um bloco inteiro preenchido
    com o byte de valor block_size (ex: 16 bytes de valor 0x10). Isso elimina ambiguidades
    na decifragem sobre onde terminava o texto original.
    
    :param data: Sequência de bytes originais da mensagem.
    :param block_size: Tamanho do bloco em bytes (padrão: 16 para AES).
    :return: Sequência de bytes alinhada a múltiplos de block_size.
    """
    if not (1 <= block_size <= 255):
        raise ValueError("O tamanho do bloco deve estar entre 1 e 255 bytes.")

    # Quantos bytes faltam para fechar o próximo múltiplo de 16?
    padding_len = block_size - (len(data) % block_size)
    
    # Cria bytes(padding_len) onde cada byte tem o valor numérico de padding_len
    # Exemplo: se faltam 3 bytes -> bytes([3, 3, 3])
    padding_bytes = bytes([padding_len] * padding_len)
    
    return data + padding_bytes


def unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Valida e remove o preenchimento PKCS#7 da mensagem decifrada.
    
    :param data: Sequência de bytes preenchida após a decifragem.
    :param block_size: Tamanho do bloco em bytes (padrão: 16).
    :return: Sequência de bytes original sem preenchimento.
    :raises ValueError: Caso o preenchimento seja nulo, inconsistente ou violado.
    """
    if not data:
        raise ValueError("Não é possível remover preenchimento de uma sequência vazia.")

    if len(data) % block_size != 0:
        raise ValueError(
            f"Tamanho dos dados ({len(data)} bytes) não é múltiplo do bloco ({block_size} bytes)."
        )

    # O último byte define exatamente quantos bytes de padding foram inseridos
    padding_len = data[-1]

    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Padding PKCS#7 inválido: tamanho fora do intervalo permitido.")

    # Validação estrita: todos os últimos 'padding_len' bytes DEVEM ser iguais a padding_len
    expected_padding = bytes([padding_len] * padding_len)
    if data[-padding_len:] != expected_padding:
        raise ValueError("Padding PKCS#7 corrompido ou chave incorreta.")

    return data[:-padding_len]