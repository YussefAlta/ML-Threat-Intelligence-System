---
tags: [config, security, secrets]
---

# Config and Secrets

All runtime configuration lives in `src/threat_intelligence/core/config.py`
as a single `Config` class of class-level attributes.

## Rule: no secret has a literal default

Every credential is read as `os.getenv('NAME')` with **no fallback value**:

- `NIST_API_KEY`, `VULNCHECK_API_KEY`, `PHISHTANK_API_KEY`, `OTX_API_KEY`
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `S3_BUCKET_NAME`

Non-secret tuning values (rate limits, URLs, timeouts) *do* carry defaults —
that is the intended distinction. A missing credential must surface as
`None` and fail loudly, never silently fall back to a baked-in value.

Secrets are supplied via `.env`, which is gitignored and has never been
tracked. `__pycache__/` is gitignored and, as of the 2026-09-30 history
rewrite, no longer tracked either.

## Why the rule exists

A literal default is how the Firecrawl key leaked — see
[[firecrawl-key-leak-remediation]]. Compiling a module with a literal
default also bakes the secret into the `.pyc`, where text-based secret
scanning will not find it.
