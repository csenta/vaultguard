"""
Shannon Entropy and Heuristic Filter Engine for VaultGuard.
Calculates information density to distinguish real cryptographic keys from documentation placeholders.
"""

from collections import Counter
import math

PLACEHOLDER_SUBSTRINGS = [
    "example", "dummy", "placeholder", "changeme", "sample", "testkey", "your_",
    "yourkey", "xxxxxx", "000000", "insert_here",
]


def shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not data:
        return 0.0

    counts = Counter(data)
    total_len = len(data)
    entropy = 0.0

    for count in counts.values():
        p = count / total_len
        entropy -= p * math.log2(p)

    return entropy


def is_likely_placeholder(candidate: str) -> bool:
    """Detects obvious dummy, mock, or placeholder tokens."""
    lower = candidate.lower()

    # Substring check
    for p in PLACEHOLDER_SUBSTRINGS:
        if p in lower:
            return True

    # Entirely trivial sequence
    if lower in ("12345678", "123456789", "1234567890", "abcdef", "abcdef123456", "1234567890123456"):
        return True

    # Check for excessive single character repetition (e.g. AAAAAAAAAAAAAA)
    if len(candidate) > 6:
        counts = Counter(candidate)
        most_common_count = counts.most_common(1)[0][1]
        if (most_common_count / len(candidate)) > 0.75:
            return True

    return False


def validate_entropy_threshold(candidate: str, min_entropy: float = 3.0) -> bool:
    """Returns True if candidate entropy meets or exceeds the minimum threshold."""
    if is_likely_placeholder(candidate):
        return False
    return shannon_entropy(candidate) >= min_entropy
