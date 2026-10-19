import re

HASH_PREFIXES: dict[str, str] = {
    "$1$": "MD5-crypt",
    "$2$": "bcrypt (original)",
    "$2a$": "bcrypt (revision with UTF-8 support)",
    "$2b$": "bcrypt (modern OpenBSD revision)",
    "$2x$": "bcrypt (bugged version compatible with crypt_blowfish)",
    "$2y$": "bcrypt (correct crypt_blowfish / PHP version)",
    "$3$": "NTHash (NTLM crypt)",
    "$5$": "SHA-256 crypt",
    "$6$": "SHA-512 crypt",
    "$argon2i$": "Argon2i",
    "$argon2d$": "Argon2d",
    "$argon2id$": "Argon2id",
    "$scrypt$": "scrypt",
    "$pbkdf2$": "PBKDF2",
    "$pbkdf2-sha256$": "PBKDF2-HMAC-SHA256",
    "$pbkdf2-sha512$": "PBKDF2-HMAC-SHA512",
    "$balloon$": "Balloon",
    "$apr1$": "Apache MD5-crypt",
    "$8$": "Cisco PBKDF2-SHA256",
    "$9$": "Cisco scrypt",
    "$ml$": "Mac OS X Salted SHA-512",
    "pbkdf2_sha256$": "Django PBKDF2-SHA256",
    "pbkdf2_sha1$": "Django PBKDF2-SHA1",
    "argon2$": "Django Argon2",
    "bcrypt$": "Django bcrypt",
    "bcrypt_sha256$": "Django bcrypt-SHA256",
    "$krb5pa$": "Kerberos 5 Pre-Authentication",
    "$krb5asrep$": "Kerberos 5 AS-REP",
    "$krb5tgs$": "Kerberos 5 TGS-REP (Kerberoasting)",
    "$pkzip$": "PKZIP Encrypted Archive",
    "$zip2$": "WinZip AES Encrypted Archive",
    "$pdf$": "PDF Document Encryption",
    "$office$": "MS Office Encrypted Document",
    "$7z$": "7-Zip Encrypted Archive",
    "$rar5$": "RAR5 Encrypted Archive",
}

HASH_PREFIX_REGEX = re.compile(r"^(\$?[a-zA-Z0-9_.-]+\$)")

PATTERNS = {
    # 1. MySQL 5
    "MySQL5": re.compile(r"^\*[0-9A-F]{40}$", re.IGNORECASE),
    # 2. DES crypt
    "DES crypt": re.compile(r"^[a-zA-Z0-9./]{13}$"),
    # 3. NetNTLMv2
    "NetNTLMv2": re.compile(
        r"^[^:]+::[^:]*:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:[0-9a-fA-F]+$"
    ),
    # 4. NetNTLMv1
    "NetNTLMv1": re.compile(
        r"^[^:]+::[^:]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]{16}$"
    ),
}

HEX_REGEX = re.compile(r"^[0-9a-fA-F]+$")

HEX_LENGTH_RULES: dict[int, list[str]] = {
    # 16 hex chars (64 bits)
    16: [
        "CRC64",
        "MySQL323",
        "Half-MD5",
        "SipHash-64",
    ],
    # 32 hex chars (128 bits)
    32: [
        "MD5",
        "NTLM",
        "MD4",
        "MD2",
        "RIPEMD-128",
        "Tiger-128",
        "Skein-128",
        "MurmurHash3-128",
    ],
    # 40 hex chars (160 bits)
    40: [
        "SHA-1",
        "RIPEMD-160",
        "HAS-160",
        "Tiger-160",
        "SHA-0",
    ],
    # 48 hex chars (192 bits)
    48: [
        "Tiger-192",
        "TTH (TigerTree Hash)",
    ],
    # 56 hex chars (224 bits)
    56: [
        "SHA-224",
        "SHA3-224",
        "Keccak-224",
    ],
    # 64 hex chars (256 bits)
    64: [
        "SHA-256",
        "SHA3-256",
        "BLAKE2s-256",
        "BLAKE2b-256",
        "RIPEMD-256",
        "Keccak-256",
        "GOST R 34.11-94",
        "GOST R 34.11-2012 (Streebog-256)",
        "Skein-256",
        "SM3",
    ],
    # 80 hex chars (320 bits)
    80: [
        "RIPEMD-320",
    ],
    # 96 hex chars (384 bits)
    96: [
        "SHA-384",
        "SHA3-384",
        "Keccak-384",
        "Skein-384",
    ],
    # 128 hex chars (512 bits)
    128: [
        "SHA-512",
        "SHA3-512",
        "BLAKE2b-512",
        "Whirlpool",
        "Keccak-512",
        "GOST R 34.11-2012 (Streebog-512)",
        "Skein-512",
    ],
    # 256 hex chars (1024 bits)
    256: [
        "Skein-1024",
    ],
}

GENERIC_PHC_REGEX = re.compile(r"^\$([a-zA-Z0-9_\-]+)\$(.*)$")

JWT_REGEX = re.compile(r"^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$")

BASE64_HINT_REGEX = re.compile(
    r"^(?=.*[+/=])[A-Za-z0-9+/]+={0,2}$"
)