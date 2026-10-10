"""Feature extraction engine for DNS query names and payloads.

Calculates Shannon entropy, string length metrics, character distribution ratios,
encoding-agnostic features (hex-only, base32-only, alphabetic-only, longest consonant run,
bigram dictionary score, label-length variance), subdomain depth, and character perplexity.
"""

from typing import Dict, Any, Tuple, List
import math
import re
import numpy as np
import pandas as pd

from backend.app.analytics.detectors import is_allowlisted_domain

CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
VOWELS = set("aeiou")
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE32_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

# Top English bigrams for language plausibility scoring
TOP_ENGLISH_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "ed", "on", "es", "st", "en", "at", "to",
    "nt", "ha", "nd", "ou", "ea", "ng", "as", "or", "ti", "is", "et", "it", "ar",
    "te", "se", "hi", "of", "me", "sa", "ne", "wa", "ve", "le", "al", "de", "ro",
    "li", "co", "ra", "ch", "ma", "ta", "ce", "ic", "ll", "na", "om", "ur", "ca"
}

FEATURE_COLUMNS = [
    "subdomain_len",
    "qname_len",
    "subdomain_depth",
    "entropy",
    "digit_ratio",
    "hex_ratio",
    "base32_ratio",
    "alphabetic_ratio",
    "longest_consonant_run",
    "bigram_dict_score",
    "label_length_variance",
    "uppercase_ratio",
    "consonant_vowel_ratio",
]


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string H(X) = -sum(p(x) * log2(p(x))).

    Args:
        text: Target string.

    Returns:
        Entropy value in bits (0.0 for empty or single char string).
    """
    if not text:
        return 0.0
    length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_base_and_subdomain(qname: str) -> Tuple[str, str]:
    """Split QNAME into subdomain and base_domain (e.g. 'sub.example.com' -> ('sub', 'example.com')).

    Args:
        qname: Full query domain name.

    Returns:
        Tuple of (subdomain, base_domain).
    """
    cleaned = qname.strip().rstrip(".").lower()
    labels = [l for l in cleaned.split(".") if l]

    if not labels:
        return "", ""
    if len(labels) == 1:
        return "", labels[0]
    if len(labels) == 2:
        return "", cleaned

    # Common multi-part TLDs (e.g. co.uk, com.au) check
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"} and len(labels[-1]) <= 3:
        base_domain = ".".join(labels[-3:])
        subdomain = ".".join(labels[:-3])
    else:
        base_domain = ".".join(labels[-2:])
        subdomain = ".".join(labels[:-2])

    return subdomain, base_domain


def calculate_longest_consonant_run(text: str) -> int:
    """Calculate the longest contiguous sequence of consonants."""
    if not text:
        return 0
    max_run = 0
    curr_run = 0
    for c in text.lower():
        if c in CONSONANTS:
            curr_run += 1
            if curr_run > max_run:
                max_run = curr_run
        else:
            curr_run = 0
    return max_run


def calculate_bigram_dict_score(text: str) -> float:
    """Calculate the ratio of bigrams matching common English words."""
    cleaned = "".join(c for c in text.lower() if c.isalpha())
    if len(cleaned) < 2:
        return 0.5  # neutral score for empty/single-char
    bigrams = [cleaned[i:i+2] for i in range(len(cleaned) - 1)]
    matches = sum(1 for b in bigrams if b in TOP_ENGLISH_BIGRAMS)
    return round(matches / len(bigrams), 4)


def calculate_label_length_variance(qname: str) -> float:
    """Calculate variance of the lengths of all labels in QNAME."""
    labels = [l for l in qname.strip().rstrip(".").split(".") if l]
    if len(labels) <= 1:
        return 0.0
    lens = [len(l) for l in labels]
    return round(float(np.var(lens)), 4)


def extract_dns_features(record: Dict[str, Any]) -> Dict[str, Any]:
    """Extract comprehensive feature vector from a single raw DNS query dictionary.

    Args:
        record: Raw DNS query dictionary.

    Returns:
        Enriched dictionary containing calculated DNS features.
    """
    qname = str(record.get("qname", "")).strip().rstrip(".")
    subdomain, base_domain = extract_base_and_subdomain(qname)

    sub_len = len(subdomain)
    qname_len = len(qname)

    # Character-class ratios and encoding-agnostic metrics
    if sub_len > 0:
        digit_count = sum(1 for c in subdomain if c.isdigit())
        hex_count = sum(1 for c in subdomain if c in HEX_CHARS)
        base32_count = sum(1 for c in subdomain if c in BASE32_CHARS)
        alpha_count = sum(1 for c in subdomain if c.isalpha())
        upper_count = sum(1 for c in subdomain if c.isupper())
        consonant_count = sum(1 for c in subdomain.lower() if c in CONSONANTS)
        vowel_count = sum(1 for c in subdomain.lower() if c in VOWELS)

        digit_ratio = digit_count / sub_len
        hex_ratio = hex_count / sub_len
        base32_ratio = base32_count / sub_len
        alphabetic_ratio = alpha_count / sub_len
        uppercase_ratio = upper_count / sub_len
        consonant_vowel_ratio = consonant_count / (vowel_count + 1)
        subdomain_entropy = calculate_shannon_entropy(subdomain)
        longest_consonants = calculate_longest_consonant_run(subdomain)
        bigram_score = calculate_bigram_dict_score(subdomain)
    else:
        digit_ratio = 0.0
        hex_ratio = 0.0
        base32_ratio = 0.0
        alphabetic_ratio = 0.0
        uppercase_ratio = 0.0
        consonant_vowel_ratio = 0.0
        subdomain_entropy = 0.0
        longest_consonants = 0
        bigram_score = 0.5

    qname_entropy = calculate_shannon_entropy(qname)
    subdomain_depth = len(subdomain.split(".")) if subdomain else 0
    label_variance = calculate_label_length_variance(qname)
    is_allowlisted = is_allowlisted_domain(base_domain) or is_allowlisted_domain(qname)

    enriched = dict(record)
    enriched.update({
        "qname": qname,
        "subdomain": subdomain,
        "base_domain": base_domain,
        "is_allowlisted": is_allowlisted,
        "subdomain_len": sub_len,
        "qname_len": qname_len,
        "subdomain_depth": subdomain_depth,
        "entropy": subdomain_entropy if sub_len > 0 else qname_entropy,
        "subdomain_entropy": subdomain_entropy,
        "qname_entropy": qname_entropy,
        "digit_ratio": round(digit_ratio, 4),
        "hex_ratio": round(hex_ratio, 4),
        "base32_ratio": round(base32_ratio, 4),
        "alphabetic_ratio": round(alphabetic_ratio, 4),
        "longest_consonant_run": longest_consonants,
        "bigram_dict_score": bigram_score,
        "label_length_variance": label_variance,
        "uppercase_ratio": round(uppercase_ratio, 4),
        "consonant_vowel_ratio": round(consonant_vowel_ratio, 4),
    })

    return enriched


def extract_features_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Enrich a Pandas DataFrame of DNS query records with features."""
    if df.empty:
        return df

    enriched_records = [extract_dns_features(row.to_dict()) for _, row in df.iterrows()]
    return pd.DataFrame(enriched_records)
