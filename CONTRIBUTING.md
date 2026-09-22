# Contributing to Regent

Thanks for looking. Two rules keep the project able to ship a commercial layer
on top of the open core without surprising anyone.

## 1. Developer Certificate of Origin (DCO)

Every commit must be signed off:

    git commit -s -m "match: support glob on tool names"

The `-s` flag adds `Signed-off-by: Your Name <you@example.com>`, which certifies
the DCO 1.1 (https://developercertificate.org): you wrote the change or have the
right to submit it under the project's license (Apache-2.0). CI rejects
unsigned commits. No separate CLA is required.

## 2. License and scope

- Everything in this repository is Apache-2.0. By contributing you license your
  contribution under Apache-2.0, including its patent grant (section 3).
- Vertical policy packs other than `dev_default` and `ria` live in a separate
  repository and are not open source. Contributions of regulatory mappings are
  welcome here; the maintainers may also ship them in paid packs. If that is
  not acceptable to you, do not contribute mappings.
- Trademarks: "Regent" and the project logo (once one exists) are trademarks
  of Regent AI Systems LLC and are not licensed under Apache-2.0. Forks must
  use a different name.

## What to work on

- Runtimes (`runtimes/`), compilers (`compilers/`), approvers, stores, and
  audit sources are the best places for outside contributions. Each has a
  Protocol in `core/ports.py` and a contract test in `tests/contract/`.
- Core (`core/`) changes need a design note in the PR description and 100%
  test coverage on the changed paths.
- Pack rules must carry `controls:` and `examiner_asks:`. Tests fail otherwise.
  Cite the rule text you mapped from (URL to the regulator's site, not a blog).

## Process

1. Open an issue first for anything beyond a small fix.
2. Branch from `main`; keep PRs under ~400 lines where possible.
3. `make check` must pass: ruff, mypy --strict, pytest, gitleaks.
4. One maintainer approval merges. Security-sensitive paths (match, workflow,
   chain, compilers) require two.

## Conduct

Be direct, be specific, be civil. Disagree with code, not people. Maintainers
will remove anyone who harasses others, once, without appeal.
