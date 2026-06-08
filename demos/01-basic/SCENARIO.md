# Demo 01 — Detecting a tripped canary

## Spirit
Like Thinkst Canarytokens: mint a unique URL/token that should *never* be
touched in normal operation, plant it somewhere tempting (a fake backup link,
a decoy salaries doc), then watch your access logs. Any hit is high-signal
evidence of recon or exfiltration. HONEYURL is **detection only** — it mints
tokens and matches access records. It performs no attacks and no network I/O.

## Files
- `registry.json` — two minted canaries under a known demo secret:
  - `prod-db-backup-link` (a planted backup URL)
  - `hr-salaries-doc` (a decoy HR document link)
- `access.log.jsonl` — four inbound access records (JSONL). One is benign
  traffic; three reference canary tokens.

## Run

Mint a fresh canary (random secret, table output):

    python -m honeyurl mint --label demo --base-url https://canary.example.net/t

Scan the demo access log against the registry:

    python -m honeyurl --format json scan \
        --registry demos/01-basic/registry.json \
        --records  demos/01-basic/access.log.jsonl

## Expected result
Three trips are detected:

| token                              | verdict   | severity |
|------------------------------------|-----------|----------|
| `a1b2c3d4e5f6071829.c0e34d994af1`  | authentic | CRITICAL |
| `0011223344556677ab.deadbeef0000`  | tampered  | HIGH     |
| `ffffffffffffffffff.000000000000`  | forged    | INFO     |

- **CRITICAL** — a valid, registered canary was accessed. Investigate the
  source IP immediately; the backup-link decoy was touched.
- **HIGH** — a registered `token_id` arrived with a *bad signature*: someone
  is mangling/guessing a real token (tampering).
- **INFO** — a token-shaped string that is neither registered nor validly
  signed: an opportunistic scan, not a real canary hit.

The benign `/healthz` record contains no token and produces no event.

Because CRITICAL/HIGH findings exist, the CLI exits **non-zero (1)** — wire it
into a SOC/CI check so a trip fails the pipeline or pages an analyst.

## Exit codes
- `0` — no actionable trips
- `1` — CRITICAL/HIGH trips detected
- `2` — usage / input error

## Scope
Static analysis of already-captured access records plus offline token minting.
No network connections, no attack traffic — defensive / authorized-testing use.
