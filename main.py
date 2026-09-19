"""
Interface de linha de comando (CLI) para execução dos processos de cifragem e decifragem do AES-128.
"""
import argparse
import sys

from src.key_expansion import expand_key
from src.padding import pad, unpad
from src.utils import parse_key, parse_ciphertext, format_ciphertext
from src.aes import cipher_block, inv_cipher_block


def encrypt_flow(message_str: str, key_bytes: bytes, output_decimal: bool) -> str:
    """Orquestra a cifragem de uma mensagem completa em blocos de 16 bytes."""
    round_keys = expand_key(key_bytes)
    
    # 1. Converte para bytes e aplica PKCS#7
    raw_data = message_str.encode("utf-8")
    padded_data = pad(raw_data)

    # 2. Cifra bloco a bloco (16 bytes)
    ciphertext_chunks = []
    for i in range(0, len(padded_data), 16):
        block = padded_data[i : i + 16]
        encrypted_block = cipher_block(block, round_keys)
        ciphertext_chunks.append(encrypted_block)

    full_ciphertext = b"".join(ciphertext_chunks)

    # 3. Formata para exibição final
    return format_ciphertext(full_ciphertext, to_decimal=output_decimal)


def decrypt_flow(cipher_input: str, key_bytes: bytes, input_decimal: bool) -> str:
    """Orquestra a decifragem de uma sequência de blocos e recupera a mensagem original."""
    round_keys = expand_key(key_bytes)

    # 1. Converte a entrada textual (hex ou decimal) em bytes
    raw_ciphertext = parse_ciphertext(cipher_input, is_decimal=input_decimal)

    # 2. Decifra bloco a bloco (16 bytes)
    decrypted_chunks = []
    for i in range(0, len(raw_ciphertext), 16):
        block = raw_ciphertext[i : i + 16]
        decrypted_block = inv_cipher_block(block, round_keys)
        decrypted_chunks.append(decrypted_block)

    full_decrypted = b"".join(decrypted_chunks)

    # 3. Remove o preenchimento PKCS#7
    unpadded_data = unpad(full_decrypted)

    # 4. Tenta decodificar para texto legível
    try:
        return unpadded_data.decode("utf-8")
    except UnicodeDecodeError:
        return f"[Bytes brutos (hex)]: {unpadded_data.hex()}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AES-128 CLI - Cifragem e Decifragem em Python Puro."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Modo de operação")

    # Comando encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Cifrar mensagem")
    enc_parser.add_argument("-m", "--message", required=True, help="Mensagem a ser cifrada")
    enc_parser.add_argument("-k", "--key", required=True, help="Chave (16 caracteres ou 32 hexadecimais)")
    enc_parser.add_argument("--key-hex", action="store_true", help="Indica que a chave passada está em formato hexadecimal")
    enc_parser.add_argument("--format", choices=["hex", "dec"], default="hex", help="Formato de saída (padrão: hex)")

    # Comando decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Decifrar mensagem")
    dec_parser.add_argument("-c", "--cipher", required=True, help="Mensagem cifrada (hexadecimal ou lista de inteiros decimais)")
    dec_parser.add_argument("-k", "--key", required=True, help="Chave (16 caracteres ou 32 hexadecimais)")
    dec_parser.add_argument("--key-hex", action="store_true", help="Indica que a chave passada está em formato hexadecimal")
    dec_parser.add_argument("--format", choices=["hex", "dec"], default="hex", help="Formato da entrada cifrada (padrão: hex)")

    args = parser.parse_args()

    try:
        key_bytes = parse_key(args.key, is_hex=args.key_hex)

        if args.command == "encrypt":
            output = encrypt_flow(
                message_str=args.message,
                key_bytes=key_bytes,
                output_decimal=(args.format == "dec")
            )
            print(f"\nMensagem Cifrada ({args.format.upper()}):")
            print(output)

        elif args.command == "decrypt":
            output = decrypt_flow(
                cipher_input=args.cipher,
                key_bytes=key_bytes,
                input_decimal=(args.format == "dec")
            )
            print("\nMensagem Decifrada:")
            print(output)

    except Exception as error:
        print(f"\n[ERRO]: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()