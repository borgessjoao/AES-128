# AES-128 Block Cipher Implementation

Integrantes do grupo:

João da Silva Borges - 831605
Ana Beatriz Oliveira Carulla - 831499


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
│   └── utils.py         # Tratamento de entradas e formatações
└── tests/
    ├── __init__.py
    └── test_vectors.py  # Testes com vetores do NIST

```

---

## 🧩 Módulos e Responsabilidades

* **`src/galois.py`:** Operações em $GF(2^8)$ com o polinómio redutor $m(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`).
* **`src/aes.py`:** Orquestração dos 10 rounds e implementação da função `mix_columns(state, matrix)`, desenhada para operar com a matriz padrão do AES ou com a matriz inversa.
* **`src/key_expansion.py`:** Expansão linear da chave de 128 bits em 44 palavras de 32 bits ($w_0$ a $w_{43}$).
* **`src/padding.py`:** Adequação de cadeias de caracteres arbitrárias para múltiplos de 16 bytes via PKCS#7.
* **`src/utils.py`:** Tratamento das entradas (aceita chaves tanto em formato texto/string de 16 caracteres quanto em representação hexadecimal de 32 caracteres) e formatação de saídas.
* **`main.py`:** Interface CLI para execução das rotinas de cifragem e decifragem via argumentos de terminal.

---

## 🚀 Como Executar (CLI)

### 1. Pré-requisitos

* Python 3.10 ou superior instalado.
* Nenhuma biblioteca externa é necessária para o algoritmo central. Apenas `pytest` para rodar a suíte de testes automatizados.

#### Configuração do Ambiente

Recomenda-se o uso de um ambiente virtual para isolamento das dependências de teste:

**No Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

```

*(Comandos de ambiente Linux/macOS)*

**No Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1  
pip install -r requirements.txt

```

*(Comandos de ambiente Windows)*

---

### 2. Cifragem (`encrypt`)

A interface permite cifrar mensagens informando a chave (em string ou em hexadecimal) e a mensagem em formato texto (string). É possível definir o formato da saída cifrada através do parâmetro `--format`.

**Parâmetros principais:**

* `-m` ou `--message`: Mensagem a ser cifrada.
* `-k` ou `--key`: Chave de 128 bits (16 caracteres ou 32 caracteres hexadecimais).
* `--key-hex`: Flag opcional indicando que a chave fornecida está em formato hexadecimal.
* `--format`: Formato da saída gerada. Aceita `hex` (padrão) ou `dec`.

**Exemplo A: Cifragem padrão (Chave String, Mensagem String $\rightarrow$ Saída Hex)**

```bash
python main.py encrypt -m "Mensagem Secreta" -k "minhachave123456"

```

*(Exemplo padrão de cifragem)*

**Exemplo B: Cifragem gerando saída Decimal (Chave String, Mensagem String $\rightarrow$ Saída Lista Decimal)**

```bash
python main.py encrypt -m "Vasco da Gama 5x0" -k "minhachave123456" --format dec

```

*(Exemplo de cifragem decimal)*

**Exemplo C: Cifragem com Chave em Hexadecimal (Mensagem String, Chave Hex $\rightarrow$ Saída Hex)**

```bash
python main.py encrypt -m "Vasco da Gama 5x0 Coritiba" -k "b7ffa33bcc5ec90d593da203fcae3a75" --key-hex

```

*(Exemplo de cifragem com chave hex)*

---

### 3. Decifragem (`decrypt`)

A decifragem recebe o texto cifrado gerado anteriormente (seja em string hexadecimal contínua ou lista de inteiros decimais) e recupera a mensagem original, permitindo apresentar o resultado em texto legível (string UTF-8) ou em bytes hexadecimais.

**Parâmetros principais:**

* `-c` ou `--cipher`: O texto cifrado (hexadecimal contínuo ou lista decimal com colchetes).
* `-k` ou `--key`: A chave utilizada na cifragem.
* `--key-hex`: Flag caso a chave fornecida seja hexadecimal.
* `--format`: Formato da entrada cifrada que está a ser fornecida (`hex` por padrão, ou `dec`).
* `--out-format`: Formato da mensagem decifrada exibida na saída (`str` por padrão, ou `hex`).



**Exemplo D: Decifragem a partir do formato Hexadecimal padrão (Saída Texto)**

```bash
python main.py decrypt -c "e61436dd9943a006265350d6f3afd39c5196d6a929a96e6aa837d6a756bf923b" -k "minhachave123456"

```

*(Exemplo de decifragem a partir de hex)*

**Exemplo E: Decifragem a partir do formato Decimal (Saída Texto)**

```bash
python main.py decrypt -c "[230, 20, 54, 221, 153, 67, 160, 6, 38, 83, 80, 214, 243, 175, 211, 156, 81, 150, 214, 169, 41, 169, 110, 106, 168, 55, 214, 167, 86, 191, 146, 59]" -k "minhachave123456" --format dec

```

*(Exemplo de decifragem a partir de dec)*

**Exemplo F: Decifragem usando Chave em Hexadecimal (Saída Texto)**

```bash
python main.py decrypt -c "c1593b8c8e82d49a718588f141581deaca238d4388d4e36e76f3c0e6a64816fa" -k "b7ffa33bcc5ec90d593da203fcae3a75" --key-hex

```

*(Exemplo de decifragem com chave hex)*

**Exemplo G: Decifragem exibindo o resultado em Hexadecimal (`--out-format hex`)**

```bash
python main.py decrypt -c "e61436dd9943a006265350d6f3afd39c5196d6a929a96e6aa837d6a756bf923b" -k "minhachave123456" --out-format hex

```

(Saída esperada: `4d656e736167656d2053656372657461`, que corresponde à representação em bytes da mensagem original)

---

## 🧪 Validação e Testes

Para validar a integridade de todas as camadas do algoritmo contra os vetores de teste oficiais do NIST FIPS-197:

```bash
pytest tests/

```

*(Comando de execução de testes)*