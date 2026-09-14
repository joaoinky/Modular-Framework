"""Reconhece formatos, nunca retorna conteúdo, fragmentos ou identificadores de segredos."""

import hashlib
from functools import lru_cache
from importlib import resources
import re
import time
import unicodedata

ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
NSEC = re.compile(r"(?<![A-Za-z0-9])nsec1[a-z0-9]{8,100}(?![A-Za-z0-9])", re.I)
WIF = re.compile(r"(?<![A-Za-z0-9])[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])")


@lru_cache(maxsize=1)
def wordlist():
    raw = resources.files("nvg_key_material").joinpath("data/bip39_english.txt").read_bytes()
    if hashlib.sha256(raw).hexdigest() != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda":
        raise ValueError("Wordlist incorporada inconsistente")
    return {word: index for index, word in enumerate(raw.decode("utf-8").splitlines())}


def polymod(values):
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for index, generator in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if top >> index & 1:
                checksum ^= generator
    return checksum


def valid_nsec(token):
    if token.lower() != token and token.upper() != token:
        return False
    token = token.lower()
    if not token.startswith("nsec1") or len(token) != 63:
        return False
    try:
        data = [BECH32.index(char) for char in token[5:]]
    except ValueError:
        return False
    hrp = [ord(c) >> 5 for c in "nsec"] + [0] + [ord(c) & 31 for c in "nsec"]
    if polymod(hrp + data) != 1:
        return False
    number = 0
    for value in data[:-6]:
        number = number << 5 | value
    # 52 grupos de cinco bits transportam 256 bits e quatro bits zero de padding.
    return number & 15 == 0 and 0 < number >> 4 < ORDER


def valid_wif(token):
    number = 0
    try:
        for char in token:
            number = number * 58 + BASE58.index(char)
        data = number.to_bytes((number.bit_length() + 7) // 8, "big")
    except ValueError:
        return False
    if len(data) not in (37, 38) or data[0] not in (0x80, 0xEF):
        return False
    payload, checksum = data[:-4], data[-4:]
    if len(payload) == 34 and payload[-1] != 1:
        return False
    return (hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
            and 0 < int.from_bytes(payload[1:33], "big") < ORDER)


def valid_mnemonic(words, vocabulary):
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    number = 0
    try:
        for word in words:
            number = number << 11 | vocabulary[word]
    except KeyError:
        return False
    check_bits = len(words) // 3
    entropy_bits = 11 * len(words) - check_bits
    entropy = (number >> check_bits).to_bytes(entropy_bits // 8, "big")
    return number & ((1 << check_bits) - 1) == hashlib.sha256(entropy).digest()[0] >> (8 - check_bits)


def detect(text, vocabulary, deadline=float("inf")):
    counts, candidates = {"nsec": 0, "wif": 0, "bip39": 0, "bunker_credential": 0}, {"nsec": 0, "wif": 0, "bunker": 0, "shamir_share": 0}
    from urllib.parse import urlsplit, parse_qs
    for match in re.finditer(r"bunker://[^\s\"'<>]+", text, re.I):
        if time.monotonic() > deadline:
            return counts, candidates, True
        try:
            url = urlsplit(match[0])
            query = parse_qs(url.query, max_num_fields=16)
            if re.fullmatch(r"[a-fA-F0-9]{64}", url.netloc) and len(query.get("secret", [])) == 1 and query["secret"][0]:
                counts["bunker_credential"] += 1
            else:
                candidates["bunker"] += 1
        except ValueError:
            candidates["bunker"] += 1
    # Não validar CRC inventado nem reunir partes: o documento não especifica
    # a codificação completa. Uma parte não demonstra exposição da seed.
    candidates["shamir_share"] = len(re.findall(r"(?<![A-Za-z0-9])nvgs[12]-[A-Za-z0-9-]+", text, re.I))
    for kind, pattern, validator in (("nsec", NSEC, valid_nsec), ("wif", WIF, valid_wif)):
        for match in pattern.finditer(text):
            if time.monotonic() > deadline:
                return counts, candidates, True
            if validator(match[0]):
                counts[kind] += 1
            else:
                candidates[kind] += 1
    # Só palavras contíguas separadas por whitespace; não recompor frases usando
    # palavras espalhadas pelo arquivo. Prefere a frase mais longa em cada posição.
    normalized = unicodedata.normalize("NFKD", text).lower()
    tokens = list(re.finditer(r"[^\W\d_]+", normalized))
    index = 0
    while index < len(tokens):
        if index % 128 == 0 and time.monotonic() > deadline:
            return counts, candidates, True
        window = []
        for offset in range(24):
            position = index + offset
            if position >= len(tokens) or tokens[position][0] not in vocabulary:
                break
            if offset and not normalized[tokens[position - 1].end():tokens[position].start()].isspace():
                break
            window.append(tokens[position][0])
        length = next((n for n in (24, 21, 18, 15, 12) if len(window) >= n and valid_mnemonic(window[:n], vocabulary)), 0)
        if length:
            counts["bip39"] += 1
        index += length or 1
    return counts, candidates, False


def safe_location(value):
    """Nome de arquivo/ID também pode conter um segredo: omitir o rótulo inteiro.

    O filtro é deliberadamente mais amplo que os validadores: inclusive um prefixo
    truncado nsec e uma sequência de 12 palavras merecem não ser persistidos.
    """
    if re.search(r"nsec1|bunker:|nvgs[12]-", value, re.I) or re.search(r"[5KL9c][1-9A-HJ-NP-Za-km-z]{45,}", value):
        return "[localização/ID omitido]"
    words = re.findall(r"[^\W\d_]+", value.lower())
    if len(words) >= 12:
        try:
            vocabulary = wordlist()
        except (OSError, ValueError):
            return "[localização/ID omitido]"
        consecutive = 0
        for word in words:
            consecutive = consecutive + 1 if word in vocabulary else 0
            if consecutive >= 12:
                return "[localização/ID omitido]"
    return value
