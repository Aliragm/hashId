# HashId

A simple and lightweight command-line interface (CLI) tool to identify hash types and cryptographic algorithms from hash strings.

## Features

- **Hex-length matching**: Identifies standard hexadecimal hash formats including MD5, SHA-1, SHA-256, SHA-512, NTLM, Keccak, Whirlpool, Skein, and others based on digest bit length.
- **Prefix and crypt matching**: Detects modular crypt formats and password hashes such as bcrypt, Argon2, scrypt, PBKDF2, Django password hashes, Cisco formats, and Kerberos digests.
- **Generic PHC support**: Recognizes generic Password Hashing Competition (PHC) string formats.
- **Non-hash detection**: Identifies common non-hash representations such as JSON Web Tokens (JWT) and Base64-encoded strings.
- **Multiple input modes**: Supports single hash arguments, batch file processing via `--file` / `-f`, and standard input piping (`stdin`).
- **Clean output**: Visual colored output indicating possible algorithm candidates, non-hash detections, or unmapped patterns.

## Installation

### Prerequisites

- Python 3.9 or higher

### Setup Virtual Environment

```bash
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### Install Dependencies

Install required dependencies:

```bash
pip install -r requirements.txt
```

To install the package in editable mode with the `hashid` command executable globally in your environment:

```bash
pip install -e .
```

## Usage

### 1. Direct Command-Line Argument

Analyze a hash string directly:

```bash
hashid 5d41402abc4b2a76b9719d911017c592
```

Or using `cli.py`:

```bash
python cli.py 5d41402abc4b2a76b9719d911017c592
```

Output:
```text
Analyzing: 5d41402abc4b2a76b9719d911017c592
Possible hash types:
  - MD5
  - NTLM
  - MD4
  - MD2
  - RIPEMD-128
  - Tiger-128
  - Skein-128
  - MurmurHash3-128
```

### 2. Batch Processing from a File

Analyze multiple hashes listed one per line in a text file:

```bash
hashid --file hashes.txt
# or
hashid -f hashes.txt
```

### 3. Standard Input (Pipe)

Pipe hashes into `hashid`:

```bash
echo "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" | hashid
```

### 4. Python Module Invocation

Invoke the module using Python's `-m` switch:

```bash
python -m hashid "$2a$12$e8KERg9vhw1k.1rTcgO1IuNq9a3lUe1.G83Vn0oN1PzJ4E/w8V/Gy"
```

### 5. Python API

Use the identification logic directly in Python code:

```python
from hashid import identify

result = identify("5d41402abc4b2a76b9719d911017c592")
print(result)
```

## Project Structure

```text
hashId/
├── hashid/
│   ├── __init__.py       # Package exports
│   ├── __main__.py       # Entry point for 'python -m hashid'
│   ├── cli.py            # Typer CLI application and formatting
│   ├── constants.py      # Hash signatures, tables, and regular expressions
│   └── identify.py       # Core hash identification logic
├── tests/
│   ├── __init__.py
│   └── test_identify.py  # Unit tests
├── cli.py                # Root CLI script runner
├── pyproject.toml        # Project metadata and console script entry point
├── requirements.txt      # Project dependencies
├── .gitignore            # Git ignore rules
└── README.md             # Project documentation
```

## Running Tests

Run the test suite with standard `unittest`:

```bash
python -m unittest discover tests
```
