# AES-128 Block Cipher Implementation

Implementação educacional e modular do algoritmo de criptografia simétrica **AES-128** (*Advanced Encryption Standard*) desenvolvida do zero em Python nativo (linha de comando), sem bibliotecas criptográficas externas.

---

## 📌 Especificações do Projeto

* **Tamanho do Bloco ($Nb$):** 128 bits (16 bytes, matriz de estado $4 \times 4$).
* **Tamanho da Chave ($Nk$):** 128 bits (16 bytes / 4 palavras de 32 bits).
* **Número de Rodadas ($Nr$):** 10 rodadas de cifragem/decifragem.
* **Subchaves:** 11 subchaves derivadas via expansão de chave.
* **Aritmética Linear:** O módulo de mistura de colunas (`MixColumns`) implementa multiplicação matricial genérica sobre $GF(2^8)$, operando com qualquer matriz constante $4 \times 4$ (atendendo tanto à cifragem quanto à decifragem).

---

## 📂 Estrutura do Repositório

```text
aes-128/
├── .gitignore
├── README.md
├── requirements.txt
├── main.py
├── src/
│   ├── __init__.py
│   ├── sbox.py          # S-Box, Inv S-Box e constantes Rcon
│   ├── galois.py        # Aritmética GF(2^8) (xtime e multiplicação modular)
│   ├── key_expansion.py # Expansão da chave de 128 bits para 11 subchaves
│   ├── aes.py           # SubBytes, ShiftRows, MixColumns genérico e AddRoundKey
│   ├── padding.py       # Preenchimento PKCS#7
│   └── utils.py         # Conversões (Hex, String, Decimal)
└── tests/
    ├── __init__.py
    └── test_vectors.py  # Testes com vetores do NIST e casos parciais

```

---

## 🧩 Módulos e Responsabilidades

* **`src/galois.py`:** Operações em $GF(2^8)$ com o polinômio redutor $m(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`).
* **`src/aes.py`:** Orquestração dos 10 rounds e implementação da função `mix_columns(state, matrix)`, desenhada para operar com a matriz padrão do AES ou com a matriz inversa.


* **`src/key_expansion.py`:** Expansão linear da chave de 128 bits em 44 palavras de 32 bits ($w_0$ a $w_{43}$).
* **`src/padding.py`:** Adequação de strings arbitrárias para múltiplos de 16 bytes via PKCS#7.
* **`src/utils.py`:** Tratamento das entradas (aceita chaves tanto em formato texto/string de 16 caracteres quanto em representação hexadecimal de 32 caracteres) e formatação de saídas.


* **`main.py`:** Interface CLI para execução das rotinas de cifragem e decifragem via argumentos de terminal.



---

## 🚀 Como Executar

### 1. Pré-requisitos

* Python 3.10 ou superior instalado.


* Nenhuma biblioteca externa é necessária para o algoritmo central. Apenas `pytest` para rodar os testes automatizados.



```bash
pip install -r requirements.txt

```

### 2. Cifragem (CLI)

A cifragem recebe uma mensagem em string e uma chave (via string ou hexadecimal), gerando a saída em hexadecimal:

* Entrada com chave em string (16 caracteres):


```bash
python main.py encrypt --key "chave16caracter" --text "Mensagem secreta para o teste"

```


* Entrada com chave em hexadecimal (32 dígitos hex):


```bash
python main.py encrypt --key-hex "000102030405060708090a0b0c0d0e0f" --text "Mensagem secreta para o teste"

```



*Saída esperada:* Sequência cifrada impressa no terminal em formato hexadecimal e/ou decimal.

---

### 3. Decifragem (CLI)

A decifragem recebe o texto cifrado em hexadecimal (ou decimal) e a chave correspondente, restaurando a string original:

* Decifrar a partir de hexadecimal:


```bash
python main.py decrypt --key-hex "000102030405060708090a0b0c0d0e0f" --cipher-hex "69c4e0d86a7b0430d8cdb78070b4c55a..."

```



---

## 🧪 Validação e Testes

Para validar a corretude contra os vetores de teste oficiais do NIST e referências públicas:

```bash
pytest tests/

```
