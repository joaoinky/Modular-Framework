import re

from nvg_key_material import safe_location


def redact(value, depth=0):
    if depth > 16:
        raise ValueError("Evidence nesting exceeded")
    if isinstance(value, str):
        if re.search(r"ncryptsec1", value, re.I):
            return "[encrypted material omitted]"
        return safe_location(value)
    if value is None or type(value) in (bool, int, float):
        return value
    if isinstance(value, list):
        return [redact(item, depth + 1) for item in value]
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        return {redact(k, depth + 1): redact(v, depth + 1) for k, v in value.items()}
    raise ValueError("Evidence must be JSON data")
