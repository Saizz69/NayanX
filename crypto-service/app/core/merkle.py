"""
Cryptographic Merkle Tree using SHA3-256 (NIST FIPS 202).

Provides:
- Deterministic Merkle tree construction over arbitrary leaves.
- Cryptographic inclusion proofs (O(log N)).
- Standalone offline inclusion proof verification.
"""

from __future__ import annotations
import hashlib
from typing import List, Dict, Any, Tuple, Optional


def sha3_256_hash(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha3_256(data).hexdigest()


def hash_pair(left_hex: str, right_hex: str) -> str:
    """
    Computes parent hash from left and right children using SHA3-256.
    Uses domain separator b"\x01" to prevent second-preimage attacks.
    """
    left_bytes = bytes.fromhex(left_hex)
    right_bytes = bytes.fromhex(right_hex)
    hasher = hashlib.sha3_256()
    hasher.update(b"\x01")
    hasher.update(left_bytes)
    hasher.update(right_bytes)
    return hasher.hexdigest()


class MerkleTree:
    """
    Complete binary SHA3-256 Merkle Tree.
    """

    def __init__(self, leaf_hashes: List[str]):
        if not leaf_hashes:
            self.leaves = [sha3_256_hash(b"EMPTY_MERKLE_TREE_ROOT")]
        else:
            self.leaves = list(leaf_hashes)

        self.levels: List[List[str]] = [self.leaves]
        self._build_tree()

    def _build_tree(self):
        current = self.leaves
        while len(current) > 1:
            next_level: List[str] = []
            for i in range(0, len(current), 2):
                left = current[i]
                # If odd number of nodes, duplicate the last node (RFC 6962 standard)
                right = current[i + 1] if i + 1 < len(current) else left
                parent = hash_pair(left, right)
                next_level.append(parent)
            self.levels.append(next_level)
            current = next_level

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def get_proof(self, leaf_index: int) -> List[Dict[str, str]]:
        """
        Generates Merkle inclusion proof for leaf at leaf_index.
        Returns list of { "sibling_hash": hex, "position": "left" | "right" }.
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError(f"Leaf index {leaf_index} out of bounds (total leaves: {len(self.leaves)})")

        proof: List[Dict[str, str]] = []
        idx = leaf_index

        for level in self.levels[:-1]:
            is_right_child = (idx % 2 == 1)
            sibling_idx = (idx - 1) if is_right_child else (idx + 1)

            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
            else:
                # Duplicated node for odd counts
                sibling_hash = level[idx]

            proof.append({
                "sibling_hash": sibling_hash,
                "position": "left" if is_right_child else "right",
            })
            idx = idx // 2

        return proof


def verify_merkle_proof(leaf_hash: str, proof: List[Dict[str, str]], root_hash: str) -> bool:
    """
    Offline verification of Merkle inclusion proof with NO service running.
    Recomputes root hash up the branch and verifies equality with expected root_hash.
    """
    current_hash = leaf_hash

    for step in proof:
        sibling = step["sibling_hash"]
        position = step["position"]

        if position == "left":
            current_hash = hash_pair(sibling, current_hash)
        else:
            current_hash = hash_pair(current_hash, sibling)

    return current_hash.lower() == root_hash.lower()
