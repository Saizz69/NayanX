"""
Tardos Fingerprinting Code Engine (Symmetric Variant).

Provides:
- Deterministic p-vector generation via HMAC expansion from doc_secret.
- Recipient codeword derivation per session: u_ij ~ HMAC-SHA256(seed_r, "slot:session:i").
- Pre-distribution SHA3-256 cryptographic commitments:
    H_p = SHA3-256(p-vector || doc_secret_salt)
    C_r = SHA3-256(codeword_bits || salt_r)
- Symmetric Tardos accusation scoring:
    y=1: x=1 -> +sqrt((1-p)/p); x=0 -> -sqrt(p/(1-p))
    y=0: x=0 -> +sqrt(p/(1-p)); x=1 -> -sqrt((1-p)/p)
- Monte Carlo threshold calibration (>=20,000 innocent trials).
- Collusion capacity simulation for collusion coalition c.
"""

from __future__ import annotations
import math
import hashlib
import hmac
import json
from typing import List, Optional, Dict, Any, Tuple
import numpy as np


DEFAULT_CUTOFF_T = 0.05


def generate_p_vector(
    doc_secret: bytes, num_slots: int, cutoff_t: float = DEFAULT_CUTOFF_T
) -> List[float]:
    """
    Derives deterministic secret vector p of length num_slots from doc_secret via HMAC-SHA256.
    Draws r ~ U[t', pi/2 - t'] with sin^2(t') = t, p_i = sin^2(r).
    Ensures p_i in [cutoff_t, 1 - cutoff_t].
    """
    if cutoff_t <= 0.0 or cutoff_t >= 0.5:
        raise ValueError("cutoff_t must be in (0, 0.5)")

    t_prime = math.asin(math.sqrt(cutoff_t))
    r_range = (math.pi / 2.0) - (2.0 * t_prime)

    p_vector: List[float] = []
    scale = float(1 << 64)

    for i in range(num_slots):
        msg = f"tardos_p_slot:{i}".encode("ascii")
        h = hmac.new(doc_secret, msg, hashlib.sha256).digest()
        u_val = int.from_bytes(h[:8], "big") / scale
        r_i = t_prime + (u_val * r_range)
        p_i = math.sin(r_i) ** 2
        p_vector.append(float(p_i))

    return p_vector


def compute_p_commitment(p_vector: List[float], doc_secret_salt: bytes) -> str:
    """
    H_p = SHA3-256(p-vector || doc_secret_salt)
    Logged once per document before distribution to prevent administrator framing.
    """
    canonical_p = json.dumps([round(x, 8) for x in p_vector], separators=(",", ":")).encode("utf-8")
    hasher = hashlib.sha3_256()
    hasher.update(canonical_p)
    hasher.update(doc_secret_salt)
    return hasher.hexdigest()


def derive_recipient_codeword(
    seed_r: bytes, session_no: int, p_vector: List[float]
) -> List[int]:
    """
    Derives recipient codeword for slot i:
    u_ij = first 8 bytes of HMAC-SHA256(seed_r, "slot"||session||i) as uniform in [0, 1)
    bit = 1 if u_ij < p_i else 0.
    """
    codeword: List[int] = []
    scale = float(1 << 64)

    for i, p_i in enumerate(p_vector):
        msg = f"slot:{session_no}:{i}".encode("ascii")
        h = hmac.new(seed_r, msg, hashlib.sha256).digest()
        u_ij = int.from_bytes(h[:8], "big") / scale
        bit = 1 if u_ij < p_i else 0
        codeword.append(bit)

    return codeword


def compute_codeword_commitment(codeword: List[int], salt_r: bytes) -> str:
    """
    C_r = SHA3-256(codeword_bits || salt_r)
    Logged per recipient before distribution completes.
    """
    bits_str = "".join(str(b) for b in codeword).encode("ascii")
    hasher = hashlib.sha3_256()
    hasher.update(bits_str)
    hasher.update(salt_r)
    return hasher.hexdigest()


def compute_accusation_score(
    candidate_bits: List[int],
    observed_vector: List[Optional[int]],
    p_vector: List[float],
) -> float:
    """
    Computes symmetric Tardos accusation score for candidate bits given observed vector:
        y=1: x=1 -> +sqrt((1-p)/p); x=0 -> -sqrt(p/(1-p))
        y=0: x=0 -> +sqrt(p/(1-p)); x=1 -> -sqrt((1-p)/p)
    Erasures (observed bit is None) are skipped.
    """
    if len(candidate_bits) != len(observed_vector) or len(p_vector) != len(observed_vector):
        raise ValueError(
            f"Dimension mismatch: candidate={len(candidate_bits)}, "
            f"observed={len(observed_vector)}, p={len(p_vector)}"
        )

    score = 0.0
    for p_i, y_i, x_i in zip(p_vector, observed_vector, candidate_bits):
        if y_i is None:
            continue

        sqrt_1_minus_p_over_p = math.sqrt((1.0 - p_i) / p_i)
        sqrt_p_over_1_minus_p = math.sqrt(p_i / (1.0 - p_i))

        if y_i == 1:
            if x_i == 1:
                score += sqrt_1_minus_p_over_p
            else:
                score -= sqrt_p_over_1_minus_p
        elif y_i == 0:
            if x_i == 0:
                score += sqrt_p_over_1_minus_p
            else:
                score -= sqrt_1_minus_p_over_p

    return float(score)


def calibrate_thresholds(
    p_vector: List[float],
    num_trials: int = 20_000,
    max_sessions: int = 2,
    target_attributed_fpr: float = 1e-3,
    target_suspected_fpr: float = 1e-2,
    active_mask: Optional[List[bool]] = None,
) -> Dict[str, Any]:
    """
    Calibrates decision thresholds via Monte Carlo simulation of innocent candidates.
    Runs at least 20,000 trials matching the actual p-vector and active non-erased slots.
    Accounting for max_sessions per candidate.
    """
    if num_trials < 20_000:
        num_trials = 20_000

    p_arr = np.array(p_vector, dtype=np.float64)
    if active_mask is not None:
        p_arr = p_arr[np.array(active_mask, dtype=bool)]

    L_eff = len(p_arr)
    if L_eff == 0:
        return {
            "num_trials": num_trials,
            "effective_slots": 0,
            "threshold_attributed": 0.0,
            "threshold_suspected": 0.0,
            "mean_innocent": 0.0,
            "std_innocent": 0.0,
            "target_attributed_fpr": target_attributed_fpr,
            "target_suspected_fpr": target_suspected_fpr,
        }

    # Simulate random observations matching p
    # For innocent candidates, E[Score] = 0 regardless of y
    # Precalculate score weights for y=1 and y=0
    w_pos = np.sqrt((1.0 - p_arr) / p_arr)  # if x == y == 1, or (y==0, x==0 -> sqrt(p/(1-p)))
    w_neg = np.sqrt(p_arr / (1.0 - p_arr))

    # Single session simulation
    # Draw innocent candidates' bits X ~ Bernoulli(p)
    # Total candidates = num_trials
    # Each candidate has up to max_sessions independent sessions
    candidate_scores = np.zeros(num_trials, dtype=np.float64)

    for session in range(max_sessions):
        # Observation y can be drawn from p_arr
        y_sim = (np.random.random(L_eff) < p_arr).astype(int)

        score_if_1 = np.where(y_sim == 1, w_pos, -w_pos)
        score_if_0 = np.where(y_sim == 1, -w_neg, w_neg)

        # X is [num_trials, L_eff]
        X = (np.random.random((num_trials, L_eff)) < p_arr).astype(np.float64)
        session_scores = np.dot(X, score_if_1 - score_if_0) + np.sum(score_if_0)
        candidate_scores += session_scores

    percentile_attr = (1.0 - target_attributed_fpr) * 100.0
    percentile_susp = (1.0 - target_suspected_fpr) * 100.0

    threshold_attr = float(np.percentile(candidate_scores, percentile_attr))
    threshold_susp = float(np.percentile(candidate_scores, percentile_susp))

    mean_innocent = float(np.mean(candidate_scores))
    std_innocent = float(np.std(candidate_scores))

    return {
        "num_trials": num_trials,
        "effective_slots": L_eff,
        "max_sessions": max_sessions,
        "target_attributed_fpr": target_attributed_fpr,
        "target_suspected_fpr": target_suspected_fpr,
        "threshold_attributed": round(threshold_attr, 4),
        "threshold_suspected": round(threshold_susp, 4),
        "t_attributed": round(threshold_attr, 4),
        "t_suspected": round(threshold_susp, 4),
        "mean_innocent": round(mean_innocent, 4),
        "std_innocent": round(std_innocent, 4),
    }


def estimate_collusion_capacity(
    num_slots: int, cutoff_t: float = DEFAULT_CUTOFF_T, target_fpr: float = 1e-3
) -> int:
    """
    Computes the largest collusion size c supported by num_slots at target_fpr.
    Derived from asymptotic symmetric Tardos bounds:
      L >= 2 * pi^2 * c^2 * ln(1 / target_fpr)
      c_max = floor( sqrt( L / (2 * pi^2 * ln(1 / target_fpr)) ) )
    """
    if num_slots < 10:
        return 1

    denom = 2.0 * (math.pi ** 2) * math.log(1.0 / target_fpr)
    c_est = int(math.floor(math.sqrt(num_slots / denom)))
    return max(1, c_est)
