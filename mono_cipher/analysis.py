"""Heuristics for monoalphabetic substitution ciphertexts (frequency mapping)."""

from collections import Counter
from typing import Dict, List, Tuple

from . import cipher

# English letter frequency descending (etaoin shrdlu...)
ENGLISH_FREQ = [
    ("E", 0.12702), ("T", 0.09056), ("A", 0.08167), ("O", 0.07507),
    ("I", 0.06966), ("N", 0.06749), ("S", 0.06327), ("H", 0.06094),
    ("R", 0.05987), ("D", 0.04253), ("L", 0.04025), ("C", 0.02782),
    ("U", 0.02758), ("M", 0.02406), ("W", 0.02360), ("F", 0.02228),
    ("G", 0.02015), ("Y", 0.01974), ("P", 0.01929), ("B", 0.01492),
    ("V", 0.00978), ("K", 0.00772), ("J", 0.00153), ("X", 0.00150),
    ("Q", 0.00095), ("Z", 0.00074),
]


def _letters_only(text: str) -> str:
    """Returns only alphabetic characters uppercased."""
    return "".join([c for c in text.upper() if c.isalpha()])


def letter_frequency(ciphertext: str) -> List[Tuple[str, float]]:
    """Returns list of (letter, freq) sorted by frequency descending from ciphertext."""
    text = _letters_only(ciphertext)
    if not text:
        return []
    counts = Counter(text)
    total = len(text)
    freq = [(ch, counts[ch] / total) for ch in counts]
    return sorted(freq, key=lambda x: x[1], reverse=True)


def guess_mapping_by_frequency(ciphertext: str) -> Dict[str, str]:
    """
    Builds a cipher->plain mapping by aligning ciphertext letter frequencies
    with English letter frequencies (highest to highest).
    """
    cipher_freq = letter_frequency(ciphertext)
    english_sorted = [letter for letter, _ in ENGLISH_FREQ]
    mapping: Dict[str, str] = {}

    for idx, (cipher_ch, _) in enumerate(cipher_freq):
        if idx < len(english_sorted):
            mapping[cipher_ch] = english_sorted[idx]

    # For any missing letters (unlikely), map them to remaining English letters
    remaining_plain = [ch for ch in english_sorted if ch not in mapping.values()]
    remaining_cipher = [ch for ch in (chr(ord("A") + i) for i in range(26)) if ch not in mapping]
    for c, p in zip(remaining_cipher, remaining_plain):
        mapping[c] = p

    return mapping


def mapping_to_key(mapping: Dict[str, str]) -> str:
    """
    Converts a cipher->plain mapping to a 26-letter substitution alphabet (plain->cipher).
    This can be fed back into cipher.encrypt/decrypt.
    """
    inverse = {plain: cipher_ch for cipher_ch, plain in mapping.items()}
    key_chars = []
    for plain in (chr(ord("A") + i) for i in range(26)):
        key_chars.append(inverse.get(plain, plain))
    return "".join(key_chars)


def apply_mapping(ciphertext: str, mapping: Dict[str, str]) -> str:
    """Applies a cipher->plain mapping directly to produce a plaintext guess."""
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            upper = ch.upper()
            plain = mapping.get(upper, upper)
            result.append(plain if ch.isupper() else plain.lower())
        else:
            result.append(ch)
    return "".join(result)


def bruteforce(ciphertext: str) -> Tuple[str, str]:
    """
    Performs frequency-based brute-force guess.

    Returns:
        (key, plaintext_guess)
        - key: 26-letter substitution alphabet (plain->cipher) derived from mapping.
        - plaintext_guess: decrypted text using the guessed mapping.
    """
    mapping = guess_mapping_by_frequency(ciphertext)
    key = mapping_to_key(mapping)
    plaintext = apply_mapping(ciphertext, mapping)
    return key, plaintext
