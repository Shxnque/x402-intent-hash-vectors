// Provider-neutral `intent_hash` verifier for x402 pre-settle intent clearance.
// TS/JS mirror of verify.py. MUST produce byte-for-byte identical digests.
// Source thread: https://github.com/x402-foundation/x402/issues/3506
// Zero runtime deps beyond node:crypto. ESM. Deterministic.
import { createHash } from "node:crypto";

const SCHEMA_VERSION = "1";
const REQUIRED = ["schema_version", "chain", "asset", "amount", "payer", "payee", "nonce", "expiry"];
const CAIP2 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
const CAIP10 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/;
const CAIP19 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}\/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}$/;

export class IntentError extends Error {}

// JCS (RFC 8785) profile for str|int|bool|object: keys sorted by code point,
// no insignificant whitespace. Floats are rejected upstream.
function canonicalize(v) {
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (v && typeof v === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

const isInt = (n) => typeof n === "number" && Number.isInteger(n);

export function validateIntent(x) {
  for (const f of REQUIRED) if (!(f in x)) throw new IntentError(`missing required field: ${f}`);
  for (const k of Object.keys(x)) if (!REQUIRED.includes(k)) throw new IntentError(`unknown field not permitted: ${k}`);
  if (x.schema_version !== SCHEMA_VERSION) throw new IntentError("schema_version must be '1'");
  if (typeof x.amount === "boolean" || !isInt(x.amount)) throw new IntentError("amount must be integer minor-units");
  if (x.amount <= 0) throw new IntentError("amount must be positive");
  if (typeof x.nonce === "boolean" || !isInt(x.nonce) || x.nonce < 0) throw new IntentError("nonce must be non-negative integer");
  if (typeof x.expiry === "boolean" || !isInt(x.expiry) || x.expiry <= 0) throw new IntentError("expiry must be positive unix seconds");
  if (!CAIP2.test(String(x.chain))) throw new IntentError("chain must be CAIP-2");
  if (!CAIP19.test(String(x.asset))) throw new IntentError("asset must be CAIP-19");
  if (!CAIP10.test(String(x.payer))) throw new IntentError("payer must be CAIP-10");
  if (!CAIP10.test(String(x.payee))) throw new IntentError("payee must be CAIP-10");
  if (String(x.asset).split("/", 1)[0] !== String(x.chain)) throw new IntentError("asset chain must equal declared chain");
}

export function computeIntentHash(intent) {
  validateIntent(intent);
  return createHash("sha256").update(canonicalize(intent), "utf8").digest("hex");
}
