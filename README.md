# x402 pre-settle `intent_hash` — provider-neutral conformance vectors

**Source thread:** [x402-foundation/x402#3506](https://github.com/x402-foundation/x402/issues/3506) — *Optional independent intent clearance on `BeforeSettleHook`*.

@SentVan23 (XAPS, live pre-settle clearance at `api.xaps.network`, `APMC1/xaps-sdk`) accepted this definition as the interoperable `intent_hash`. This directory is the **provider-neutral reference** promised in-thread: a recomputable commitment the counterparty can verify **without trusting the payer**.

## The commitment

```
intent_hash = sha256( JCS(canonical_intent) )   # lower-case hex
```

Pinned rules (from the thread):

| Field | Rule |
|---|---|
| canonicalisation | JCS (RFC 8785) profile over string/integer fields |
| `amount` | **integer minor-units only** — no floats, no decimal strings, no bool |
| `chain` | CAIP-2 (e.g. `eip155:8453`) |
| `asset` | CAIP-19 (e.g. `eip155:8453/erc20:0x8335…`) |
| `payer` / `payee` | CAIP-10 |
| cross-chain | asset CAIP-19 chain component MUST equal the declared CAIP-2 `chain` |
| unknown / missing | fail closed |

The intent envelope is:

```json
{
  "schema_version": "1",
  "chain":   "eip155:8453",
  "asset":   "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "amount":  1500000,
  "payer":   "eip155:8453:0xA0b8991216c7f43F7F7cC0C6D2f3aBc3D2b6a111",
  "payee":   "eip155:8453:0xF977814e90dA44bFA03b6295A0616a897441aceC",
  "nonce":   7,
  "expiry":  1789730000
}
```

## Why it matters

An opaque `receipt_id` in a header is only a *locator*. The commitment has to live in signed fields the counterparty can recompute. `intent_hash` binds the **payment intent** (who moves what value, to whom, until when) so a `BeforeSettleHook` (or an independent clearance service) can prove the settled call is the authorised one — not merely well-formed.

## Run

```bash
python run_vectors.py     # exit 0 = conformant
# or one-off:
echo '{...intent...}' | python verify.py
```

`verify.py` has **zero third-party dependencies** and is deterministic (same input → same digest). A TypeScript `verify()` mirrors it 1:1 (same JCS profile, same digest) so Py and TS implementations interoperate byte-for-byte.

## Vectors

11 vectors: 3 positive (incl. a key-reorder equivalence pair proving canonicalisation, and an amount-delta proving hash sensitivity) + 8 negative (float amount, decimal-string amount, negative amount, non-CAIP-2 chain, cross-chain asset smuggle, missing field, unknown field, bool amount). Each is `declared inputs → deterministic outcome`, so the set doubles as a regression suite.

> Status: reference published for interop. Next: mirror `verify()` in TS in `APMC1/xaps-sdk` shape and link both from #3506.
