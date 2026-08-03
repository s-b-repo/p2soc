# Contributing to pi2soc

## Before your first commit

Activate the local secrets-scrub hook **in this checkout**:

```sh
git config core.hooksPath .githooks
```

You only need to do this once per clone. Without it, your commit may
slip a secret into git history, where rotating it after the fact is the
only fix.

If you prefer the `pre-commit` framework, install it instead — the
config in `.pre-commit-config.yaml` calls the same hook:

```sh
pip install pre-commit
pre-commit install
```

## Never commit

The hook blocks these paths by default:

- `.env`, `.env.*` — runtime secrets
- `secret/` — host-sealed material
- `PROMPT.txt` — operator scratchpad
- `.claude/` — harness state
- `MEMORY.md` — Claude Code's persistent memory
- `*.key`, `*_ed25519` — private keys

And these content patterns:

- the operator's canary sudo password
- `BEGIN (RSA|EC|OPENSSH) PRIVATE KEY` PEM blocks
- `sk-...` (OpenAI / Anthropic-shaped API keys)
- `ghp_...` / `ghs_...` (GitHub PATs / app tokens)

### Fixture escape

A documented example file that legitimately *describes* the shape of a
secret without holding one (e.g. `.env.example`) passes the hook if the
matching line contains the literal string `EXAMPLE-OK`:

```sh
# .env.example
DATABASE_PASSWORD=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx   # EXAMPLE-OK
```

## Before every push

```sh
make lint
make test
```

There is no remote CI yet — you are the CI. Pre-push your branch only
after both pass.

## Running the scrub manually

```sh
make secrets-scan        # runs the hook on the current staged set
```

Useful as a final sanity check before `git push`.

## Reviewing your own diff

```sh
git diff --staged
git log --oneline -5
```

Eyeball the staged diff for anything that looks like a credential, an
absolute path under `/home/<your-username>`, or an IP / hostname you
don't want pinned in history.

## Code style

- Python: stdlib first; PyGObject for GUI; `pytest` for tests; no `pip`-
  installed deps in `setup.py` (it runs before the venv exists).
- Shell: `set -e` at the top, `bash -n` clean (`make lint` enforces).
- Tests: fakes over mocks; mirror `FakeBackend` in `conftest.py` when
  you add a new backend method.

## Architecture pointers

- `docs/ARCHITECTURE.md` — runtime topology and module map.
- `docs/SECURITY.md` — secret-store model, kiosk-lock, blocked URLs.
- `docs/WIZARD.md` — first-run flow and every panel option.
- `CHANGELOG.md` — what shipped, when, why.

When in doubt, grep the codebase for the closest existing pattern and
adapt — the project leans hard on consistency over novelty.
