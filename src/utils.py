"""
Módulo utilitário para conversão, sanitização e formatação de formatos de entrada e saída.
Atende aos requisitos de manipulação de chave e mensagens em texto, hexadecimal ou decimal.
"""
import re


def parse_key(key_input: str, is_hex: bool) -> bytes:
    """
    Processa a entrada da chave e retorna exatamente 16 bytes brutos.
    
    :param key_input: Chave fornecida pelo usuário (texto puro ou dígitos hexadecimais).
    :param is_hex: Se True, interpreta a entrada como hexadecimal; caso contrário, como string UTF-8.
    :return: Chave em exatamente 16 bytes.
    :raises ValueError: Caso a chave não contenha exatamente 16 bytes (128 bits).
    """
    if is_hex:
        # Remove eventuais espaços, prefixos '0x' ou quebras de linha
        sanitized_hex = key_input.strip().lower().replace("0x", "").replace(" ", "")
        
        if len(sanitized_hex) != 32:
            raise ValueError(
                f"Chave hexadecimal inválida: esperava 32 caracteres hexadecimais (16 bytes), "
                f"mas recebeu {len(sanitized_hex)}."
            )
        try:
            raw_key = bytes.fromhex(sanitized_hex)
        except ValueError as exc:
            raise ValueError(f"A chave contém caracteres hexadecimais inválidos: {exc}") from exc
    else:
        # Converte string direta em bytes (UTF-8)
        raw_key = key_input.encode("utf-8")
        if len(raw_key) != 16:
            raise ValueError(
                f"Chave em string inválida: esperava exatamente 16 caracteres ASCII/bytes, "
                f"mas recebeu {len(raw_key)} bytes."
            )

    return raw_key


def parse_ciphertext(cipher_input: str, is_decimal: bool) -> bytes:
    """
    Converte a mensagem cifrada recebida em string hexadecimal ou valores decimais para bytes brutos.
    
    :param cipher_input: String contendo os dados cifrados (hex contínuo ou decimais separados por vírgula/espaço).
    :param is_decimal: Se True, processa como lista de inteiros decimais; se False, como hexadecimal.
    :return: Sequência de bytes brutos decodificados.
    :raises ValueError: Caso os dados estejam corrompidos ou não sejam múltiplos de 16 bytes.
    """
    cleaned_input = cipher_input.strip()

    if is_decimal:
        # Extrai todos os números inteiros decimais (aceita separadores como vírgula, espaço ou colchetes)
        tokens = re.findall(r"\d+", cleaned_input)
        if not tokens:
            raise ValueError("Nenhum valor numérico decimal foi encontrado na entrada.")
        
        byte_list = []
        for token in tokens:
            val = int(token)
            if not (0 <= val <= 255):
                raise ValueError(f"Valor decimal fora do intervalo de byte (0 a 255): {val}")
            byte_list.append(val)
        
        raw_bytes = bytes(byte_list)
    else:
        # Processa formato hexadecimal contínuo ou com espaços
        sanitized_hex = cleaned_input.lower().replace("0x", "").replace(" ", "").replace("\n", "")
        if len(sanitized_hex) % 2 != 0:
            raise ValueError("Tamanho de string hexadecimal ímpar. Cada byte exige exatamente 2 dígitos hex.")
        try:
            raw_bytes = bytes.fromhex(sanitized_hex)
        except ValueError as exc:
            raise ValueError(f"A entrada contém caracteres hexadecimais inválidos: {exc}") from exc

    if len(raw_bytes) == 0 or len(raw_bytes) % 16 != 0:
        raise ValueError(
            f"O tamanho dos dados cifrados ({len(raw_bytes)} bytes) não é um múltiplo do bloco do AES (16 bytes)."
        )

    return raw_bytes


def format_ciphertext(data: bytes, to_decimal: bool) -> str:
    """
    Formata os bytes cifrados para exibição em formato hexadecimal ou lista decimal.
    
    :param data: Sequência de bytes cifrados.
    :param to_decimal: Se True, formata como lista de números decimais; se False, como string hexadecimal contínua.
    :return: Representação textual formatada dos dados.
    """
    if to_decimal:
        # Retorna representação em vetor decimal legível: ex: [105, 196, 224, ...]
        return "[" + ", ".join(str(b) for b in data) + "]"
    
    # Retorna hexadecimal em minúsculas contínuo: ex: "69c4e0d86a7b..."
    return data.hex()