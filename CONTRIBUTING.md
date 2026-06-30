# Contributing to Prismor Warden

Thanks for helping make AI agents safer to run. The highest-leverage
contribution is a **new detection rule** — every rule you add becomes a guard
that protects every Prismor user. This is the open coverage model: the community
extends the ruleset the way the Sigma, Falco, and Semgrep communities do.

## Quick dev setup

```bash
git clone https://github.com/PrismorSec/prismor
cd prismor
python3 -m pip install -e .
python3 -m pytest -q          # run the suite
python3 scripts/check_oss_safe.py   # OSS-safety guard (no secrets/keys committed)
```

## Contributing a detection rule

Rules live in [`warden/default_policy.yaml`](warden/default_policy.yaml) and follow
the schema in [`warden/policy_schema.json`](warden/policy_schema.json). A rule is:

```yaml
- id: kebab-case-id              # unique, stable
  severity: CRITICAL             # CRITICAL | HIGH | MEDIUM | LOW
  category: secret_exfiltration  # one of the documented categories
  title: One-line human description of what this blocks
  event_types: [shell]           # shell | network | file_read | file_write | prompt | tool_result | skill_manifest
  fields: [command]              # which event fields the patterns match against
  patterns:
    - 'regex that matches the dangerous payload'   # Python `re` syntax
```

**Rules ship in OBSERVE mode by default** — they log a would-be block but never
break a user until an operator promotes them to enforce. So a good detection that
occasionally over-matches is safe to land; a missed detection is the real cost.

### Requirements for a rule PR

1. **A test.** Every rule PR must add a test that proves the rule fires on the
   malicious case **and** does not fire on a benign look-alike. Add it under
   [`tests/`](tests/) (see `tests/test_detection_improvements.py` for the
   pattern). False positives erode trust faster than false negatives — prove both
   directions.
2. **Evidence.** In the PR description, link the real attack/technique the rule
   defends against (advisory, write-up, or a reproduction).
3. **Patterns matched against argument *values*, not `key=value`** — the
   `command` field carries the argument value only. (A common gotcha: a
   word-boundary regex like `\brm -rf /` fails to match `=rm -rf /`.)
4. **No weakening of core rules.** Rules in the non-overridable floor are
   add-only — you may strengthen (add patterns), never disable.

### How rules are reviewed

`python3 -m pytest -q` is the CI gate; your test is the proof. A maintainer
reviews for over-matching, severity/category fit, and floor safety. Curated,
signed, real-time threat intel ships in the commercial feed — community rules are
the open baseline everyone gets.

## Contributing a framework adapter

Adapters live in [`adapters/`](adapters/) and are **MIT-licensed** for maximum
reuse. An adapter wraps a framework's tool-execution surface and routes each call
through `warden.runtime.evaluate_tool_call()`. Mirror an existing adapter
(`adapters/langchain`, `adapters/openai-agents`) and add a test under `tests/`.

## Security & the open-core boundary

- **Never commit secrets or private keys.** `scripts/check_oss_safe.py` runs in
  CI and as a recommended pre-commit hook; it blocks PEM private keys, cloud
  credentials, and the signing key from entering the public repo.
- See [`OPEN_CORE.md`](OPEN_CORE.md) for what lives in the open runtime vs the
  commercial control plane.
- Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md).

## License of contributions

Contributions to the runtime are accepted under the repository's root license
(Apache-2.0); contributions to `adapters/` under MIT. By submitting a PR you
agree your contribution is licensed under the applicable license.
