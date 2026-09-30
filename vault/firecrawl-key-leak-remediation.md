---
tags: [security, git, secrets, incident]
---

# Firecrawl API Key Leak Remediation

Date: 2026-09-30

## What leaked

`fc-70b3...1730` (Firecrawl API key), hardcoded in
`src/threat_intelligence/core/config.py`. Present in 27 commits, all on
public `origin/main`.

## Root cause

Key was committed as a literal default. Commit `789233f` ("Guard Firecrawl
API key via env") moved the *source* to `os.getenv`, and `ed63eb6` dropped
the Firecrawl code entirely — but neither removed the value from history,
and neither touched the compiled copy.

## The gotcha: filter-repo skips binary blobs

`git filter-repo --replace-text` **silently ignores blobs it detects as
binary**. A committed `__pycache__/config.cpython-313.pyc` embedded the key
as a plain string and survived the first rewrite untouched — while a text
`grep` over the working tree reported the repo "clean".

Two lessons:
- Scan for secrets with `strings` over **every blob**, not `git grep` over
  text. `git grep` misses compiled artifacts entirely.
- `__pycache__/` was tracked despite being in `.gitignore` (added to the
  index before the ignore rule existed). Ignore rules do not untrack.

Fix was a second pass: `--invert-paths --path-glob '*__pycache__/*'
--path-glob '*.pyc'`, removing build artifacts from all history.

## Outcome

- All 28 commits preserved; rewritten `HEAD` tree is byte-identical to the
  original except the removed `__pycache__/`.
- Force-pushed `main` and `feature/github-enrichment`.
- **Orphaned commits remain fetchable from GitHub by SHA.** Verified after
  the push: the old commit still served the key. A force-push does not
  delete anything on GitHub — only GitHub Support can purge the objects.

## Standing rule

Rewriting history does not revoke a credential. Once a secret reaches a
public remote, rotation at the provider is the only real fix; the git
cleanup is hygiene. Revoke first, scrub second.

See [[config-and-secrets]] for how keys are loaded at runtime.
