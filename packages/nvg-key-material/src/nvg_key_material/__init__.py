"""Pure recognition and bounded local reads; no audit-engine dependencies."""

from .patterns import detect, safe_location, valid_mnemonic, valid_nsec, valid_wif, wordlist

__version__ = "0.1.0"
__all__ = ["detect", "safe_location", "valid_mnemonic", "valid_nsec", "valid_wif", "wordlist"]
