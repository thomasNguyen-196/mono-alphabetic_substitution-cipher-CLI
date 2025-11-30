"""Core monoalphabetic substitution cipher logic."""

import string
from typing import Dict, List

ALPHABET = string.ascii_uppercase


def _normalize_key(key: str) -> List[str]:
    """
    Validates and normalizes a substitution key.

    The key must contain exactly 26 alphabetic characters, covering every letter
    exactly once (case-insensitive). Returns the key as an uppercase list of
    length 26 aligned with A-Z.
    """
    letters = [ch for ch in key if ch.isalpha()]
    if len(letters) != 26:
        raise ValueError("Key must contain exactly 26 alphabetic characters.")
    letters = [ch.upper() for ch in letters]
    if len(set(letters)) != 26:
        raise ValueError("Key must not contain duplicate letters.")
    return letters


def _build_maps(key: str) -> Dict[str, Dict[str, str]]:
    """Builds forward and inverse maps for substitution."""
    normalized = _normalize_key(key)
    forward = {plain: subst for plain, subst in zip(ALPHABET, normalized)}
    inverse = {subst: plain for plain, subst in forward.items()}
    return {"forward": forward, "inverse": inverse}


def encrypt(plaintext: str, key: str) -> str:
    """
    Encrypts plaintext using monoalphabetic substitution.

    Args:
        plaintext: Text to encrypt.
        key: A 26-letter substitution alphabet (e.g., QWERTY...).

    Returns:
        Encrypted ciphertext.
    """
    maps = _build_maps(key)["forward"]
    result = []
    for ch in plaintext:
        if ch.isalpha():
            upper = ch.upper()
            subst = maps[upper]
            result.append(subst if ch.isupper() else subst.lower())
        else:
            result.append(ch)
    return "".join(result)


def decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypts ciphertext using monoalphabetic substitution.

    Args:
        ciphertext: Text to decrypt.
        key: The same 26-letter substitution alphabet used for encryption.

    Returns:
        Decrypted plaintext.
    """
    maps = _build_maps(key)["inverse"]
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            upper = ch.upper()
            plain = maps[upper]
            result.append(plain if ch.isupper() else plain.lower())
        else:
            result.append(ch)
    return "".join(result)


def validate_key(key: str) -> bool:
    """Returns True if the key is a valid 26-letter permutation, else raises."""
    _normalize_key(key)
    return True
