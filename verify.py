"""Provider-neutral `intent_hash` reference verifier for x402 pre-settle intent clearance.

Context: x402-foundation/x402#3506 (Optional independent intent clearance on
BeforeSettleHook). @SentVan23 (XAPS, api.xaps.network) accepted this definition as
the interoperable `intent_hash`. The commitment pinned in-thread:

  * canonicalisation: JCS (RFC 8785) profile over string/integer fields
  * amounts: integer minor-units ONLY (no decimals, no floats)
  * chain: CAIP-2   (e.g. "eip155:8453")
  * asset: CAIP-19  (e.g. "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
  * accounts: CAIP-10

`intent_hash` = sha256( JCS(canonical_intent) ), lower-case hex.

The hash is a *recomputable commitment* the counterparty can verify WITHOUT
trusting the payer: given the same declared intent fields, any implementation
(Py / TS / other) MUST derive the same 64-char hex digest. This file is the
normative Python reference; a TS `verify()` mirrors it 1:1.

Zero third-party dependencies. Deterministic. Same input -> same output.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SCHEMA_VERSION = "1"

# ---- field grammar (validated BEFORE hashing; invalid intent => no hash) ----
CAIP2_RE = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")
CAIP10_RE = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$")
CAIP19_RE = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}$")

REQUIRED_FIELDS = (
    "schema_version", "chain", "asset", "amount", "payer", "payee", "nonce", "expiry",
)


class IntentError(ValueError):
    """Raised when a declared intent violates the grammar (fail-closed)."""


def _canonicalize(obj: Any) -> str:
    """JCS (RFC 8785) profile for our value space: str | int | bool | dict | list.

    Object keys are sorted by Unicode code point; no insignificant whitespace;
    integers emitted without exponent. Floats are rejected upstream, so we never
    hit RFC 8785's number-formatting edge cases.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate_intent(intent: dict[str, Any]) -> None:
    """Fail-closed structural validation. Raises IntentError on any violation."""
    missing = [f for f in REQUIRED_FIELDS if f not in intent]
    if missing:
        raise IntentError(f"missing required field(s): {missing}")
    extra = [k for k in intent if k not in REQUIRED_FIELDS]
    if extra:
        raise IntentError(f"unknown field(s) not permitted: {extra}")

    if intent["schema_version"] != SCHEMA_VERSION:
        raise IntentError(f"schema_version must be '{SCHEMA_VERSION}'")

    # amount MUST be an integer number of minor-units. Reject bool, float, decimal-string.
    amount = intent["amount"]
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise IntentError("amount must be an integer (minor-units); no floats/strings/decimals")
    if amount <= 0:
        raise IntentError("amount must be a positive integer of minor-units")

    nonce = intent["nonce"]
    if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
        raise IntentError("nonce must be a non-negative integer")

    expiry = intent["expiry"]
    if isinstance(expiry, bool) or not isinstance(expiry, int) or expiry <= 0:
        raise IntentError("expiry must be a positive unix-seconds integer")

    if not CAIP2_RE.match(str(intent["chain"])):
        raise IntentError("chain must be a CAIP-2 id (e.g. eip155:8453)")
    if not CAIP19_RE.match(str(intent["asset"])):
        raise IntentError("asset must be a CAIP-19 id (e.g. eip155:8453/erc20:0x...)")
    if not CAIP10_RE.match(str(intent["payer"])):
        raise IntentError("payer must be a CAIP-10 account id")
    if not CAIP10_RE.match(str(intent["payee"])):
        raise IntentError("payee must be a CAIP-10 account id")

    # asset chain-namespace must agree with the declared chain (no cross-chain smuggling).
    if str(intent["asset"]).split("/", 1)[0] != str(intent["chain"]):
        raise IntentError("asset CAIP-19 chain component must equal the declared CAIP-2 chain")


def compute_intent_hash(intent: dict[str, Any]) -> str:
    """Validate then return the lower-case hex sha256 of the JCS canonical form."""
    validate_intent(intent)
    canonical = _canonicalize(intent)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


if __name__ == "__main__":  # pragma: no cover
    import sys
    data = json.load(sys.stdin)
    print(compute_intent_hash(data))
