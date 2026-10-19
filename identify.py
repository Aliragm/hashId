from hashes_constants import HASH_PREFIXES
from hashes_constants import HASH_PREFIX_REGEX
from hashes_constants import PATTERNS
from hashes_constants import HEX_REGEX
from hashes_constants import HEX_LENGTH_RULES
from hashes_constants import GENERIC_PHC_REGEX
from hashes_constants import JWT_REGEX
from hashes_constants import BASE64_HINT_REGEX

def indentify(hash: str):
    prefix_tables_result = prefix_tables(hash)
    if prefix_tables_result:
        return prefix_tables_result
    special_shapes_result = special_shapes(hash)
    if special_shapes_result:
        return special_shapes_result
    hex_length_rules_result = hex_length_rules(hash)
    if hex_length_rules_result:
        return hex_length_rules_result
    generic_phc_result = generic_phc(hash)
    if generic_phc_result:
        return generic_phc_result
    is_not_hash_result = is_not_hash(hash)
    if is_not_hash_result:
        return is_not_hash_result
    else:
        return None

def prefix_tables(hash: str):
    
    match = HASH_PREFIX_REGEX.match(hash.strip())

    if not match:
        return None

    prefix = match.group(1)

    algoritm = HASH_PREFIXES.get(prefix)

    if algoritm is None:
        return None

    return HASH_PREFIXES[prefix]

def special_shapes(hash: str):

    for name, regex in PATTERNS.items():
        if regex.match(hash.strip()):
            return name

    return None

def hex_length_rules(hash: str):
    if not is_pure_hex(hash):
        return None

    return HEX_LENGTH_RULES.get(len(hash.strip()))

def generic_phc(hash: str):
    match = GENERIC_PHC_REGEX.match(hash.strip())

    if not match:
        return None

    algo_name = match.group(1)
    remaining = match.group(2)

    if not remaining:
        return None

    return f"Generic PHC algoritm: {algo_name}"

def is_not_hash(hash: str):

    if JWT_REGEX.match(hash.strip()):
        return "Probable JSON Web Token (JWT), not a hash."

    if len(hash.strip()) >= 4 and len(hash.strip()) % 4 == 0 and BASE64_HINT_REGEX.match(hash.strip()):
        return "Probable Base64-encoded string, not a hash."

    return None

def is_pure_hex(hash: str):
    return bool(HEX_REGEX.fullmatch(hash))
