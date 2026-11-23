# Bad-pattern audit

`scripts/audit-bad-patterns.sh` runs a regex matrix of risky Rust patterns over
the workspace and reports what it finds. It is vendored from the `rustsploit`
repo so both projects scan the same matrix; keep them in sync when the upstream
matrix changes.

```sh
cd rust
bash scripts/audit-bad-patterns.sh            # full report
bash scripts/audit-bad-patterns.sh --section E   # one section
bash scripts/audit-bad-patterns.sh --strict      # exit non-zero on a strict hit
bash scripts/audit-bad-patterns.sh --files list.txt   # restrict to listed files
```

The `audit` GitHub workflow runs it in warn-only mode on configured branch pushes and pull requests and
posts the breakdown to the job summary. It never fails the build.

## What it scans

Production code only. The script drops `#[cfg(test)]` blocks and whole
test-only modules (`#[cfg(test)] mod foo;`), because test assertions
(`assert!`, `.unwrap()`) are deliberate there, not defects.

Sections, strict ones marked `*`: A\* panicking error handling, B\* silent error
swallowing, C\* lint suppression, D index/slice panics, E numeric/unsafe casts,
F async/blocking, G logging, H HTTP, I iterators, J style/secrets, L\* crypto,
M\* injection, N\* UB/concurrency, O\* performance, P API hygiene.

## Fixing a hit

Fix it properly — do not suppress:

- Narrowing `as` casts → `try_from` and handle the error; lossless widening →
  `u64::from` / `usize::from`.
- `x[0]` / `&x[..n]` → `.get(..)` and handle `None`.
- Production `.unwrap()` / `.expect()` → return a `Result`.
- `.lock().unwrap()` → `.lock().unwrap_or_else(std::sync::PoisonError::into_inner)`.

## `// audit-allow:`

When a match is genuinely correct — a lossless cast, an infallible call, a
best-effort cleanup, a display-only `String` error, or an irreducible FFI block
the safe bindings do not cover — put `// audit-allow: <one-line reason>` on the
same line. The script skips those, so the strict count reflects only new,
unreviewed matches. Every `// audit-allow:` must name a real reason; a reviewer
reads them.

### Irreducible `unsafe`

Nearly all syscalls go through `rustix` (safe) and signals through
`signal-hook`, so the crates carry no `unsafe` of their own — except:

- `soc-sys` — one process-wide credential-drop (`setuid`/`setgid`/`setgroups`);
  `rustix` offers only per-thread variants.
- `soc-wall::gui::ffi` — GTK/WebKit C calls (the content-filter store,
  `webkit_authentication_request_authenticate`, `gtk_window_set_wmclass`) that
  gtk-rs / webkit2gtk 0.18 do not wrap.

Each is confined to the smallest possible function, carries a `// SAFETY:`
comment, and is tagged `// audit-allow:`.

The development guide lists the release checks alongside the regex audit. [Development](../../docs/DEVELOPMENT.md)
