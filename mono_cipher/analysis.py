"""Heuristics for analyzing Vigenere ciphertexts (Kasiski, IC, frequency)."""

from collections import Counter, defaultdict
from typing import List, Tuple

from . import cipher

ENGLISH_FREQ = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253, "E": 0.12702,
    "F": 0.02228, "G": 0.02015, "H": 0.06094, "I": 0.06966, "J": 0.00153,
    "K": 0.00772, "L": 0.04025, "M": 0.02406, "N": 0.06749, "O": 0.07507,
    "P": 0.01929, "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150, "Y": 0.01974,
    "Z": 0.00074,
}

COMMON_WORDS = [
    " the ", " and ", " to ", " of ", " that ", " is ", " in ", " it ",
    " for ", " you ", " with ", " on ", " have ", " be ", " as ", " at "
]


def _letters_only(text: str) -> str:
    """Returns only alphabetic characters uppercased."""
    return "".join([c for c in text.upper() if c.isalpha()])


def kasiski_examination(ciphertext: str, min_len: int = 3, max_len: int = 5, max_key: int = 16) -> List[Tuple[int, int]]:
    """
    Finds repeated sequences and returns likely key-length factors (factor, count), sorted by count desc.
    """
    text = _letters_only(ciphertext)
    repeats = defaultdict(list)
    for size in range(min_len, max_len + 1):
        for i in range(len(text) - size + 1): # Sliding windows
            seq = text[i:i + size]
            repeats[seq].append(i) # Store positions (starting indeces) of each sub-string in (cipher)text

    distances = []
    for positions in repeats.values():
        if len(positions) < 2: # Need at least two occurrences to measure distance
            continue
        for i in range(len(positions) - 1): # Compute distances between each pair of occurrences
            distances.append(positions[i + 1] - positions[i])

    factors = Counter() # hashmap of factor -> count
    for d in distances:
        for f in range(2, max_key + 1):
            if d % f == 0:
                factors[f] += 1
    return sorted(factors.items(), key=lambda x: x[1], reverse=True) # Sort by count descending - data structure is (factor, count)


def index_of_coincidence(seq: str) -> float:
    """Computes the IC for a sequence of letters (already uppercase)."""
    n = len(seq)
    if n <= 1:
        return 0.0
    counts = Counter(seq)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1)) # IC formula


def average_ic_for_keylen(ciphertext: str, key_len: int) -> float:
    """Splits text into cosets by key_len and returns average IC."""
    text = _letters_only(ciphertext)
    if key_len <= 0:
        return 0.0
    buckets = [[] for _ in range(key_len)]
    for idx, ch in enumerate(text):
        buckets[idx % key_len].append(ch)
    ics = [index_of_coincidence("".join(bucket)) for bucket in buckets if len(bucket) > 1]
    return sum(ics) / len(ics) if ics else 0.0


def chi_square_score(seq: str, shift: int) -> float:
    """
    Chi-square score for a given Caesar shift applied to seq (seq is uppercase letters).
    Lower is better.
    """
    if not seq:
        return float("inf")
    shifted_counts = Counter()
    for ch in seq:
        shifted = (ord(ch) - ord("A") - shift) % 26 # Reverse Caesar shift
        shifted_counts[chr(shifted + ord("A"))] += 1
    n = len(seq)
    score = 0.0
    for letter, expected_freq in ENGLISH_FREQ.items():
        observed = shifted_counts.get(letter, 0) # The 0 parameter is the default value if letter not found
        expected = expected_freq * n
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score


def derive_key_for_length(ciphertext: str, key_len: int) -> str:
    """Finds best key (as uppercase letters) for a given length using chi-square per coset."""
    text = _letters_only(ciphertext)
    buckets = [[] for _ in range(key_len)] # Create cosets (2D list)
    for idx, ch in enumerate(text):
        buckets[idx % key_len].append(ch)

    key_chars = []
    for bucket in buckets:
        seq = "".join(bucket)
        best_shift = min(range(26), key=lambda s: chi_square_score(seq, s)) # Find shift (26 values 0 - 25) with lowest chi-square
        key_chars.append(chr(best_shift + ord("A")))
    return "".join(key_chars)


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


def candidate_key_lengths(ciphertext: str, max_key_len: int = 16, top_ic: int = 5) -> List[int]:
    """
    Returns a merged list of candidate key lengths using IC ranking and Kasiski factors.
    """
    ic_scores = [(k, average_ic_for_keylen(ciphertext, k)) for k in range(1, max_key_len + 1)]
    ic_scores.sort(key=lambda x: x[1], reverse=True) # Sort by IC descending
    kasiski = kasiski_examination(ciphertext, max_key=max_key_len)

    candidates = []
    for k, _ in ic_scores[:top_ic]: # Top 5 IC scores
        candidates.append(k)
    for k, _ in kasiski[:top_ic]: # Top 5 Kasiski factors
        candidates.append(k)

    seen = set()
    uniq = []
    for k in candidates:
        if k not in seen and k >= 1:
            uniq.append(k)
            seen.add(k)
    return uniq


def bruteforce(ciphertext: str, max_key_len: int = 16, top: int = 10) -> List[Tuple[int, str, str]]:
    """
    Attempts to recover key/plaintext pairs. Returns list of tuples (score, key, plaintext) sorted by score desc.
    """
    results = []
    for k in candidate_key_lengths(ciphertext, max_key_len=max_key_len):
        key = derive_key_for_length(ciphertext, k)
        plaintext = cipher.vigenere_decrypt(ciphertext, key)
        score = english_score(plaintext)
        results.append((score, key, plaintext))
    results.sort(reverse=True, key=lambda x: x[0])
    return results[:top]

# Algorithmic Flow of analysis.py:

# 1. Kasiski Examination:
#    - Locate repeated substrings of length 3–5 in the ciphertext.
#    - Compute distances between their occurrences.
#    - Distances whose factors repeat frequently indicate likely key lengths.

# 2. Index of Coincidence (IC):
#    - For each possible key length, split the ciphertext into cosets.
#    - Compute IC for each coset and average the values.
#    - Correct key lengths produce IC values close to English (≈0.065), 
#      while incorrect lengths behave like random text (≈0.038).

# 3. Candidate Key Lengths:
#    - Merge top Kasiski factors and highest-IC lengths.
#    - Deduplicate results and preserve priority ordering.

# 4. Chi-Square Analysis:
#    - For each coset under each candidate key length, test all 26 Caesar shifts.
#    - Compute chi-square deviation from English letter frequency.
#    - The shift with the lowest score is the most likely.

# 5. Key Derivation:
#    - Combine best shifts for all cosets to reconstruct the full Vigenère key.

# 6. English Scoring:
#    - Decrypt the ciphertext with the derived key.
#    - Score plaintext using common English phrases and high-frequency letters.
#    - Higher scores indicate more natural English.

# 7. Brute Force Attempt:
#    - For each candidate key length: derive key → decrypt → score.
#    - Sort results by English score and return top candidates.

# This workflow systematically combines classical cryptanalytic heuristics
# (Kasiski, Friedman IC, chi-square analysis) to reverse-engineer Vigenère keys.
