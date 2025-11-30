"""Heuristics for monoalphabetic substitution ciphertexts (frequency + hill-climb search)."""

import random
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

COMMON_WORDS = [
    " the ", " and ", " to ", " of ", " that ", " is ", " in ", " it ",
    " for ", " you ", " with ", " on ", " have ", " be ", " as ", " at "
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


def english_score(text: str) -> int:
    """
    Heuristic score for English-likeness: common words weight + common letters.
    """
    lower = " " + text.lower() + " "
    score = 0
    for word in COMMON_WORDS:
        score += lower.count(word) * 10
    freq = {char: lower.count(char) for char in "etaoinshrdlu"}
    score += sum(freq.values())
    return score


def _swap_mapping(mapping: Dict[str, str], a: str, b: str) -> Dict[str, str]:
    """Returns a copy with plaintext assignments for cipher letters a/b swapped."""
    new_map = mapping.copy()
    pa, pb = new_map.get(a), new_map.get(b)
    if pa is None or pb is None:
        return new_map
    new_map[a], new_map[b] = pb, pa
    return new_map


def _hill_climb(ciphertext: str, initial_map: Dict[str, str], max_iter: int = 2000, stagnation: int = 400) -> Tuple[int, Dict[str, str], str]:
    """
    Simple hill-climb: random swaps that improve english_score are accepted.
    Returns (score, mapping, plaintext).
    """
    best_map = initial_map
    best_plain = apply_mapping(ciphertext, best_map)
    best_score = english_score(best_plain)

    current_map = best_map
    current_score = best_score
    steps_since_improve = 0

    for _ in range(max_iter):
        c1, c2 = random.sample(cipher.ALPHABET, 2)
        cand_map = _swap_mapping(current_map, c1, c2)
        cand_plain = apply_mapping(ciphertext, cand_map)
        cand_score = english_score(cand_plain)
        if cand_score > current_score:
            current_map = cand_map
            current_score = cand_score
            steps_since_improve = 0
            if cand_score > best_score:
                best_map = cand_map
                best_plain = cand_plain
                best_score = cand_score
        else:
            steps_since_improve += 1
            if steps_since_improve >= stagnation:
                break
    return best_score, best_map, best_plain


def _seed_mappings(ciphertext: str) -> List[Dict[str, str]]:
    """Builds a handful of seed mappings by swapping among top-frequency cipher letters."""
    base = guess_mapping_by_frequency(ciphertext)
    seeds = [base]
    top_cipher = [ch for ch, _ in letter_frequency(ciphertext)][:6]
    swap_pairs = [(a, b) for idx, a in enumerate(top_cipher) for b in top_cipher[idx + 1:]]
    random.shuffle(swap_pairs)
    for a, b in swap_pairs[:6]:  # limit seed explosion
        seeds.append(_swap_mapping(base, a, b))
    return seeds


def bruteforce(ciphertext: str, restarts_per_seed: int = 3, top: int = 5) -> List[Tuple[int, str, str]]:
    """
    Frequency seeding + hill-climb refinement.

    Returns:
        List of (score, key, plaintext) sorted by score desc.
    """
    if not ciphertext:
        return []

    results: List[Tuple[int, str, str]] = []
    for seed in _seed_mappings(ciphertext):
        for _ in range(restarts_per_seed):
            score, mapping, plaintext = _hill_climb(ciphertext, seed)
            key = mapping_to_key(mapping)
            results.append((score, key, plaintext))

    # Deduplicate by key while keeping highest score per key
    best_by_key: Dict[str, Tuple[int, str]] = {}
    for score, key, plaintext in results:
        if key not in best_by_key or score > best_by_key[key][0]:
            best_by_key[key] = (score, plaintext)

    collapsed = [(score, key, plain) for key, (score, plain) in best_by_key.items()]
    collapsed.sort(reverse=True, key=lambda x: x[0])
    return collapsed[:top]
