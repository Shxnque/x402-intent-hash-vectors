"""Conformance runner: asserts every vector in vectors.json behaves as declared.

Usage:  python run_vectors.py
Exit 0 = all vectors pass (implementation is conformant). Exit 1 = drift.

Each vector is `declared inputs -> deterministic outcome`, so this doubles as a
regression suite for any x402 pre-settle `intent_hash` implementation.
"""
from __future__ import annotations

import json
import pathlib
import sys

from verify import IntentError, compute_intent_hash

HERE = pathlib.Path(__file__).parent
VECTORS = json.loads((HERE / "vectors.json").read_text())


def main() -> int:
    passed = failed = 0
    for v in VECTORS["vectors"]:
        name = v["name"]
        intent = v["intent"]
        expect = v["expect"]
        try:
            got = compute_intent_hash(intent)
            if expect["result"] != "valid":
                print(f"FAIL {name}: expected reject ({expect.get('reason')}), got hash {got}")
                failed += 1
                continue
            if got != expect["intent_hash"]:
                print(f"FAIL {name}: hash mismatch\n   expected {expect['intent_hash']}\n   got      {got}")
                failed += 1
                continue
            print(f"PASS {name}: valid -> {got}")
            passed += 1
        except IntentError as e:
            if expect["result"] == "reject":
                print(f"PASS {name}: rejected as expected ({e})")
                passed += 1
            else:
                print(f"FAIL {name}: expected valid, rejected ({e})")
                failed += 1

    # Cross-check: the two canonicalisation-equivalent vectors MUST share a hash.
    eqv = [v for v in VECTORS["vectors"] if v.get("equivalence_class") == "canon-A"]
    if len(eqv) >= 2:
        hashes = {compute_intent_hash(v["intent"]) for v in eqv}
        if len(hashes) == 1:
            print(f"PASS canon-equivalence: {len(eqv)} orderings -> 1 hash {hashes.pop()}")
            passed += 1
        else:
            print(f"FAIL canon-equivalence: orderings produced {len(hashes)} distinct hashes")
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
