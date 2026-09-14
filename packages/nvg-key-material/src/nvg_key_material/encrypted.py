"""NIP-49 envelope structure only: no decryption or password validation."""

from .patterns import BECH32, polymod


def ncryptsec_format(token):
    """Return valid/invalid/unsupported, without returning payload bytes."""
    if token.lower() != token and token.upper() != token:
        return "invalid"
    token = token.lower()
    if not token.startswith("ncryptsec1") or len(token) != 162:
        return "invalid"
    try:
        data = [BECH32.index(char) for char in token[10:]]
    except ValueError:
        return "invalid"
    hrp = [ord(c) >> 5 for c in "ncryptsec"] + [0] + [ord(c) & 31 for c in "ncryptsec"]
    if polymod(hrp + data) != 1:
        return "invalid"
    number = 0
    for value in data[:-6]:
        number = (number << 5) | value
    # 146 groups encode 728 payload bits and two zero padding bits.
    if number & 3:
        return "invalid"
    payload = (number >> 2).to_bytes(91, "big")
    if payload[0] != 2:
        return "unsupported"
    if payload[1] == 0 or payload[42] not in (0, 1, 2):
        return "invalid"
    return "valid"
