"""
Threshold Co-Signing Engine (k-of-n ML-DSA-65).

Provides:
- Independent validator identities with local post-quantum keypairs (default 2-of-3).
- Threshold signature generation on block headers.
- Standalone threshold signature verification.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

from app import config
from app.core.pqc import PQCEngine, b64_encode, b64_decode


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class ValidatorManager:
    """
    Manages local validator keypairs and performs threshold ML-DSA-65 co-signing.
    Default: 2-of-3 threshold.
    """

    DEFAULT_VALIDATOR_IDS = [
        "validator-node-alpha-1",
        "validator-node-bravo-2",
        "validator-node-charlie-3",
    ]

    def __init__(self, storage_path: Optional[Path | str] = None):
        if storage_path:
            self.storage_path = Path(storage_path)
        else:
            self.storage_path = config.DATA_DIR / "validators.json"

        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_validators()

    def _ensure_validators(self):
        """Initializes 3 validator keypairs if not already present on disk."""
        if not self.storage_path.exists():
            validators = {}
            for vid in self.DEFAULT_VALIDATOR_IDS:
                pk, sk = PQCEngine.generate_dsa_keypair()
                validators[vid] = {
                    "validator_id": vid,
                    "algorithm": "ML-DSA-65 (FIPS 204)",
                    "public_key": b64_encode(pk),
                    "private_key": b64_encode(sk),
                }
            self.storage_path.write_text(json.dumps(validators, indent=2), encoding="utf-8")

    def _load_validators(self) -> Dict[str, Dict[str, str]]:
        if not self.storage_path.exists():
            self._ensure_validators()
        return json.loads(self.storage_path.read_text(encoding="utf-8"))

    def get_public_keys(self) -> Dict[str, str]:
        """Returns mapping of validator_id -> public_key base64."""
        validators = self._load_validators()
        return {vid: data["public_key"] for vid, data in validators.items()}

    def sign_block_header(
        self, header_dict: Dict[str, Any], count: int = 2
    ) -> List[Dict[str, str]]:
        """
        Signs canonical block header with 'count' distinct validators (default: 2).
        Returns list of signature objects.
        """
        validators = self._load_validators()
        all_ids = list(validators.keys())
        if count > len(all_ids):
            raise ValueError(f"Requested {count} signatures, but only {len(all_ids)} validators available.")

        selected_ids = all_ids[:count]
        header_bytes = canonical_json(header_dict).encode("utf-8")

        signatures: List[Dict[str, str]] = []
        for vid in selected_ids:
            v_data = validators[vid]
            sk_bytes = b64_decode(v_data["private_key"])
            sig_bytes = PQCEngine.dsa_sign(sk_bytes, header_bytes)
            signatures.append({
                "validator_id": vid,
                "algorithm": "ML-DSA-65 (FIPS 204)",
                "public_key": v_data["public_key"],
                "signature": b64_encode(sig_bytes),
            })

        return signatures

    @classmethod
    def verify_threshold_signatures(
        cls,
        header_dict: Dict[str, Any],
        signatures: List[Dict[str, str]],
        trusted_public_keys: Optional[Dict[str, str]] = None,
        threshold: int = 2,
    ) -> bool:
        """
        Verifies that at least 'threshold' distinct valid ML-DSA-65 signatures are present.
        Works offline without access to private keys.
        """
        if not signatures or len(signatures) < threshold:
            return False

        header_bytes = canonical_json(header_dict).encode("utf-8")
        seen_validators = set()
        valid_count = 0

        for item in signatures:
            vid = item.get("validator_id")
            sig_b64 = item.get("signature")
            pk_b64 = item.get("public_key")

            if not vid or not sig_b64:
                continue

            # Ensure distinct validator
            if vid in seen_validators:
                continue

            # If trusted public keys are supplied, verify public key matches
            if trusted_public_keys and vid in trusted_public_keys:
                if trusted_public_keys[vid] != pk_b64:
                    continue

            try:
                pk_bytes = b64_decode(pk_b64)
                sig_bytes = b64_decode(sig_b64)
                is_valid = PQCEngine.dsa_verify(pk_bytes, header_bytes, sig_bytes)
                if is_valid:
                    seen_validators.add(vid)
                    valid_count += 1
            except Exception:
                continue

        return valid_count >= threshold
