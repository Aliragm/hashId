from hashid.constants import (
    BASE64_HINT_REGEX,
    GENERIC_PHC_REGEX,
    HASH_PREFIXES,
    HASH_PREFIX_REGEX,
    HEX_LENGTH_RULES,
    HEX_REGEX,
    JWT_REGEX,
    PATTERNS,
)


def identify(hash_str: str) -> list[str] | str | None:
    clean = hash_str.strip().strip("'\"")
    if not clean:
        return None

    checks = (
        prefix_tables,
        special_shapes,
        hex_length_rules,
        generic_phc,
        is_not_hash,
    )

    for check in checks:
        result = check(clean)
        if result:
            return result

    return None


def prefix_tables(clean_hash: str) -> list[str] | None:
    match = HASH_PREFIX_REGEX.match(clean_hash)
    if not match:
        return None

    prefix = match.group(1)
    algo = HASH_PREFIXES.get(prefix)

    if algo:
        return [algo]
    return None


def special_shapes(clean_hash: str) -> list[str] | None:
    for name, regex in PATTERNS.items():
        if regex.match(clean_hash):
            return [name]
    return None


def hex_length_rules(clean_hash: str) -> list[str] | None:
    if not is_pure_hex(clean_hash):
        return None
    return HEX_LENGTH_RULES.get(len(clean_hash))


def generic_phc(clean_hash: str) -> list[str] | None:
    match = GENERIC_PHC_REGEX.match(clean_hash)
    if not match:
        return None

    algo_name = match.group(1)
    remaining = match.group(2)

    if not remaining:
        return None

    return [f"Generic PHC: {algo_name}"]


def is_not_hash(clean_hash: str) -> str | None:
    if JWT_REGEX.match(clean_hash):
        return "Not a hash: Probable JSON Web Token (JWT)"

    if (
        len(clean_hash) >= 4
        and len(clean_hash) % 4 == 0
        and BASE64_HINT_REGEX.match(clean_hash)
    ):
        return "Not a hash: Probable Base64-encoded string"

    return None


def is_pure_hex(clean_hash: str) -> bool:
    return bool(HEX_REGEX.fullmatch(clean_hash))
