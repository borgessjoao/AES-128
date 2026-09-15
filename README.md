# AES-256 Block Cipher Implementation

Implementação educacional e modular do algoritmo de criptografia simétrica **AES-256** (*Advanced Encryption Standard*) desenvolvida do zero em Python nativo, sem bibliotecas criptográficas externas.

---

## 📌 Visão Geral da Especificação

O AES-256 opera sobre blocos fixos de dados com chaves simétricas, seguindo os parâmetros definidos no **FIPS PUB 197 (NIST)**:

* **Tamanho do Bloco ($Nb$):** 128 bits (16 bytes, organizados em uma matriz de estado $4 \times 4$).
* **Tamanho da Chave ($Nk$):** 256 bits (32 bytes / 8 palavras de 32 bits).
* **Número de Rodadas ($Nr$):** 14 rodadas de cifragem/decifragem.
* **Número Total de Subchaves:** 15 subchaves de 128 bits geradas no processo de expansão.

---

## 📂 Estrutura do Repositório

```text
aes-256/
├── .gitignore
├── README.md
├── requirements.txt
├── main.py
├── src/
│   ├── __init__.py
│   ├── sbox.py
│   ├── galois.py
│   ├── key_expansion.py
│   ├── aes.py
│   ├── padding.py
│   └── modes.py
└── tests/
    ├── __init__.py
    └── test_vectors.py

```

---

## 🧩 Responsabilidades dos Módulos

### `src/sbox.py`

Armazena as tabelas fixas de substituição não linear:

* `SBOX`: Matriz $16 \times 16$ (256 valores em hexadecimal) para o passo `SubBytes`.
* `INV_SBOX`: Tabela inversa para o passo de descriptografia `InvSubBytes`.
* Vetor `RCON`: Constantes de rodada usadas na expansão de chave.

### `src/galois.py`

Implementa a aritmética sobre o corpo finito $GF(2^8)$ com polinômio irredutível $m(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`):

* Multiplicação por $\{02\}$ (`xtime`) com rotação de bits e redução por XOR condicional.
* Multiplicação modular genérica em $GF(2^8)$ para suportar os coeficientes da decifragem ($\{09\}$, $\{0b\}$, $\{0d\}$, $\{0e\}$).

### `src/key_expansion.py`

Executa o algoritmo de expansão de chave de 256 bits:

* `rot_word()`: Rotação circular de bytes à esquerda em uma palavra de 4 bytes.
* `sub_word()`: Substituição de cada byte de uma palavra usando a `SBOX`.
* `expand_key()`: Gera a sequência de 60 palavras de 32 bits ($4 \times (14 + 1)$), aplicando a regra específica do AES-256 que inclui uma aplicação extra de `SubWord` a cada 8 palavras ($i \pmod 8 == 4$).

### `src/aes.py`

Contém as rotinas centrais do *cipher* sobre a matriz de estado $4 \times 4$:

* `sub_bytes()` / `inv_sub_bytes()`: Substituição byte a byte via S-Box.
* `shift_rows()` / `inv_shift_rows()`: Translação cíclica das linhas da matriz.
* `mix_columns()` / `inv_mix_columns()`: Transformação linear matricial das colunas em $GF(2^8)$.
* `add_round_key()`: Operação XOR entre a matriz de estado e a subchave da rodada correspondente.
* `encrypt_block()` e `decrypt_block()`: Orquestração dos 14 rounds (Round Inicial $\rightarrow$ 13 Rounds Padrão $\rightarrow$ Round Final sem MixColumns).

### `src/padding.py`

Garante o alinhamento de mensagens com tamanho arbitrário para múltiplos exatos de 16 bytes:

* `pad()`: Aplica a norma **PKCS#7** (adiciona $N$ bytes de valor $N$).
* `unpad()`: Valida e remove o padding de forma estrita no processo de decifragem.

### `src/modes.py`

Implementa os modos de operação de cifra de bloco para evitar as vulnerabilidades do modo ECB:

* **CBC (Cipher Block Chaining):** Utiliza Vetor de Inicialização (IV) aleatório de 16 bytes e encadeamento via XOR entre blocos consecutivos.
* Funções auxiliares de divisão e reconstrução de blocos contínuos.

### `tests/test_vectors.py`

Conjunto de testes automatizados com base nos vetores de teste oficiais do NIST SP 800-38A:

* Validação cruzada de chave, texto plano e texto cifrado exatos.
* Testes de regressão para `padding`, `key_expansion` e inversão simétrica (`decrypt(encrypt(m)) == m`).

### `main.py`

Ponto de entrada do sistema via linha de comando (CLI):

* Leitura de parâmetros via terminal (chaves hexadecimais, texto puro ou arquivos binários).
* Suporte aos comandos `encrypt` e `decrypt`.

---

## 🚀 Como Executar

### 1. Clonar o repositório

```bash
git clone https://github.com/usuario/aes-256.git
cd aes-256

```

### 2. Instalar dependências (testes e utilitários)

```bash
pip install -r requirements.txt

```

### 3. Rodar os testes de validação do NIST

```bash
pytest tests/

```

### 4. Exemplos de Uso

**Cifrar uma mensagem:**

```bash
python main.py encrypt \
  --key "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" \
  --mode cbc \
  --text "Mensagem secreta para testes" \
  --output "cifrado.bin"

```

**Decifrar um arquivo:**

```bash
python main.py decrypt \
  --key "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" \
  --mode cbc \
  --input "cifrado.bin"

```