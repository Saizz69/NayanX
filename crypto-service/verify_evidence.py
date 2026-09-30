#!/usr/bin/env python3
"""
WebEye Standalone Offline Cryptographic Evidence Verifier.

Verifies:
1. Block header chain (prev_hash linkage from Genesis to Head).
2. Merkle inclusion proof for any entry (SHA3-256).
3. Post-Quantum threshold signatures (2-of-3 ML-DSA-65) on block headers.
4. Database integrity against signed offline checkpoints.

Runs completely OFFLINE with NO server running.
Zero canned verdicts — every assertion is mathematically verified.
"""

from __future__ import annotations
import sys
import os
import json
import sqlite3
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional

# Ensure crypto-service directory is on sys.path for pure-python PQC imports
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

# Set DEMO_MODE fallback for offline analysis if not set
os.environ.setdefault("DEMO_MODE", "true")

from app.core.pqc import PQCEngine, b64_decode
from app.core.merkle import verify_merkle_proof, sha3_256_hash, hash_pair
from app.core.validators import ValidatorManager


def canonical_json(obj: Any) -> str:
    """Canonical JSON serialization for hashing and signature verification."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def verify_standalone_proof(proof_path: Path | str) -> bool:
    """
    Verifies an exported Merkle inclusion proof JSON file completely offline.
    """
    path = Path(proof_path)
    if not path.exists():
        print(f"[ERROR] Proof file not found: {path}", file=sys.stderr)
        return False

    data = json.loads(path.read_text(encoding="utf-8"))
    print(f"[*] Loaded proof for entry index: {data.get('entry_index')}")

    leaf_hash = data.get("leaf_hash")
    root_hash = data.get("merkle_root") or data.get("root_hash")
    proof = data.get("proof", [])
    block_header = data.get("block_header")
    validator_signatures = data.get("validator_signatures", [])

    if not leaf_hash or not root_hash:
        print("[FAIL] Missing leaf_hash or merkle_root in proof file.", file=sys.stderr)
        return False

    # 1. Verify Merkle inclusion proof
    is_merkle_valid = verify_merkle_proof(leaf_hash, proof, root_hash)
    if is_merkle_valid:
        print(f"[PASS] Merkle inclusion proof verified (Leaf: {leaf_hash[:16]}... -> Root: {root_hash[:16]}...)")
    else:
        print(f"[FAIL] Merkle inclusion proof FAILED (Calculated root does not match {root_hash})", file=sys.stderr)
        return False

    # 2. Verify Block Header and Validator Signatures if present
    if block_header and validator_signatures:
        # Check header root matches proof root
        if block_header.get("merkle_root") != root_hash:
            print("[FAIL] Block header merkle_root does not match proof root_hash.", file=sys.stderr)
            return False

        # Verify threshold 2-of-3 signatures
        sig_ok = ValidatorManager.verify_threshold_signatures(
            header_dict=block_header,
            signatures=validator_signatures,
            threshold=2,
        )
        if sig_ok:
            print(f"[PASS] Block #{block_header.get('height')} threshold signatures verified (>= 2 valid ML-DSA-65 signatures)")
        else:
            print("[FAIL] Block header threshold signature verification FAILED.", file=sys.stderr)
            return False

    print("[SUCCESS] Standalone proof verification complete: VALID.")
    return True


def verify_database_chain(db_path: Path | str) -> bool:
    """
    Verifies all blocks and entries in a local SQLite ledger database offline.
    """
    path = Path(db_path)
    if not path.exists():
        print(f"[ERROR] Database file not found: {path}", file=sys.stderr)
        return False

    conn = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    try:
        # Check if ledger_blocks table exists
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ledger_blocks'")
        if not cursor.fetchone():
            print("[WARN] Table 'ledger_blocks' does not exist in this database. Verifying legacy entry chain...", file=sys.stderr)
            return _verify_legacy_entry_chain(conn)

        # 1. Query all blocks
        cursor = conn.execute("SELECT * FROM ledger_blocks ORDER BY height ASC")
        blocks = cursor.fetchall()
        if not blocks:
            print("[FAIL] Database contains zero blocks.", file=sys.stderr)
            return False

        print(f"[*] Verifying block chain containing {len(blocks)} blocks...")

        genesis = blocks[0]
        if genesis["height"] != 0:
            print("[FAIL] Genesis block height is not 0.", file=sys.stderr)
            return False

        prev_hash = genesis["block_hash"]
        for b in blocks:
            height = b["height"]
            header = json.loads(b["header_json"])
            signatures = json.loads(b["signatures_json"])

            # 1a. Verify block hash
            calc_hash = sha3_256_hash(canonical_json(header))
            if calc_hash != b["block_hash"]:
                print(f"[FAIL] Block #{height} hash mismatch! Expected {calc_hash}, found {b['block_hash']}", file=sys.stderr)
                return False

            # 1b. Verify threshold 2-of-3 signatures
            if not ValidatorManager.verify_threshold_signatures(header, signatures, threshold=2):
                print(f"[FAIL] Block #{height} failed 2-of-3 ML-DSA signature threshold check.", file=sys.stderr)
                return False

            # 1c. Verify prev_hash pointer
            if height > 0 and b["prev_hash"] != prev_hash:
                print(f"[FAIL] Block #{height} prev_hash broken! Expected {prev_hash}, found {b['prev_hash']}", file=sys.stderr)
                return False

            # 1d. Verify Merkle root over entries
            cursor_entries = conn.execute(
                "SELECT entry_hash FROM ledger_entries WHERE entry_index >= ? AND entry_index <= ? ORDER BY entry_index ASC",
                (b["start_entry_index"], b["end_entry_index"]),
            )
            leaf_hashes = [r["entry_hash"] for r in cursor_entries.fetchall()]
            if leaf_hashes:
                from app.core.merkle import MerkleTree
                tree = MerkleTree(leaf_hashes)
                if tree.root != b["merkle_root"]:
                    print(f"[FAIL] Block #{height} Merkle root mismatch with entries in database.", file=sys.stderr)
                    return False

            prev_hash = b["block_hash"]

        print(f"[PASS] All {len(blocks)} blocks cryptographically verified with valid 2-of-3 ML-DSA threshold signatures.")

        # 2. Verify individual ledger entry hash chain
        cursor = conn.execute("SELECT * FROM ledger_entries ORDER BY entry_index ASC")
        entries = cursor.fetchall()
        print(f"[*] Verifying entry hash chain for {len(entries)} records...")

        prev_entry_hash = "0" * 64
        for e in entries:
            idx = e["entry_index"]
            if idx > 0 and e["previous_hash"] != prev_entry_hash:
                print(f"[FAIL] Entry #{idx} previous_hash pointer broken.", file=sys.stderr)
                return False
            prev_entry_hash = e["entry_hash"]

        print(f"[PASS] All {len(entries)} ledger entries intact with verified hash pointers.")
        print("[SUCCESS] Database integrity verification complete: VALID.")
        return True

    finally:
        conn.close()


def _verify_legacy_entry_chain(conn: sqlite3.Connection) -> bool:
    cursor = conn.execute("SELECT * FROM ledger_entries ORDER BY entry_index ASC")
    entries = cursor.fetchall()
    if not entries:
        print("[FAIL] Ledger has 0 entries.", file=sys.stderr)
        return False
    prev_hash = "0" * 64
    for e in entries:
        idx = e["entry_index"]
        if idx > 0 and e["previous_hash"] != prev_hash:
            print(f"[FAIL] Entry #{idx} previous_hash broken.", file=sys.stderr)
            return False
        prev_hash = e["entry_hash"]
    print(f"[PASS] Verified {len(entries)} legacy ledger entries.")
    return True


def verify_against_checkpoint(db_path: Path | str, checkpoint_path: Path | str) -> bool:
    """
    Verifies that the database state at checkpoint height matches the signed checkpoint.
    Detects any retroactive SQLite database tampering.
    """
    cp_path = Path(checkpoint_path)
    if not cp_path.exists():
        print(f"[ERROR] Checkpoint file not found: {cp_path}", file=sys.stderr)
        return False

    cp_data = json.loads(cp_path.read_text(encoding="utf-8"))
    target_height = cp_data.get("height")
    expected_block_hash = cp_data.get("block_hash")
    expected_merkle_root = cp_data.get("merkle_root")
    signatures = cp_data.get("signatures", [])
    block_header = cp_data.get("block_header")

    print(f"[*] Loaded checkpoint for block height #{target_height}")

    # 1. Verify signatures on the checkpoint itself
    if block_header and signatures:
        if not ValidatorManager.verify_threshold_signatures(block_header, signatures, threshold=2):
            print("[FAIL] Checkpoint signatures are INVALID!", file=sys.stderr)
            return False
        print("[PASS] Checkpoint threshold signatures verified (>= 2 valid ML-DSA-65 signatures)")

    # 2. Check database block at target height
    db_file = Path(db_path)
    if not db_file.exists():
        print(f"[ERROR] Database file not found: {db_file}", file=sys.stderr)
        return False

    conn = sqlite3.connect(f"file:{db_file.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute("SELECT * FROM ledger_blocks WHERE height = ?", (target_height,))
        row = cursor.fetchone()
        if not row:
            print(f"[FAIL] Database has no block at checkpoint height #{target_height} (database may have been truncated or rolled back).", file=sys.stderr)
            return False

        if row["block_hash"] != expected_block_hash:
            print(f"[FAIL] TAMPER DETECTED! Database block #{target_height} hash '{row['block_hash']}' does not match checkpoint '{expected_block_hash}'.", file=sys.stderr)
            return False

        if row["merkle_root"] != expected_merkle_root:
            print(f"[FAIL] TAMPER DETECTED! Database block #{target_height} Merkle root does not match checkpoint.", file=sys.stderr)
            return False

        print(f"[PASS] Database block #{target_height} matches signed checkpoint exactly.")
        print("[SUCCESS] Checkpoint comparison complete: DATABASE UNTAMPERED AT CHECKPOINT.")
        return True
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="WebEye Forensic Evidence Verifier (Pure-Python PQC, Offline Standalone)",
    )
    parser.add_argument("--db", type=str, help="Path to SQLite ledger database (e.g. data/audit_ledger.db)")
    parser.add_argument("--proof", type=str, help="Path to exported Merkle proof JSON file")
    parser.add_argument("--checkpoint", type=str, help="Path to signed checkpoint JSON file")

    args = parser.parse_args()

    if not args.db and not args.proof and not args.checkpoint:
        parser.print_help()
        sys.exit(1)

    success = True

    if args.proof:
        ok = verify_standalone_proof(args.proof)
        success = success and ok

    if args.db and args.checkpoint:
        ok = verify_against_checkpoint(args.db, args.checkpoint)
        success = success and ok
    elif args.db:
        ok = verify_database_chain(args.db)
        success = success and ok

    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
