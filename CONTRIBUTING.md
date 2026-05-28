# Contributing to IAGA Sentinel

Thanks for considering a contribution. IAGA Sentinel is a zero-trust
governance kernel for autonomous AI agents. We optimize for: deterministic
behavior, signed audit trails, and honest enforcement posture. Anything
that strengthens those properties is welcome.

## Quick start

```bash
git clone https://github.com/EdoardoBambini/IAGA-Sentinel
cd IAGA-Sentinel

# Build everything
cargo build --workspace

# Run the full test suite
cargo test --workspace
cargo test -p iaga-sentinel-reasoning --features ml

# Lint
cargo clippy --workspace --all-targets -- -D warnings
```

The default build uses no native ML deps. To exercise the ONNX backend
locally, add `--features ml` to `cargo build` / `cargo test` for the
`iaga-sentinel-reasoning` crate.

## What we accept

- **Bug fixes** with a regression test.
- **Documentation** improvements.
- **New features** that fit the architecture documented in
  [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md).
- **Performance** improvements with a reproducible benchmark.

## ADRs are required for non-trivial changes

If your change introduces a new capability, alters a public trait, or
shifts an architectural boundary, add an ADR under
[`docs/adr/`](docs/adr/) following the numbering and template of the
existing ones (0001–0014, 0009 is intentionally unused). Keep it
short: context, decision,
consequences, what's deliberately out of scope.

A PR that touches architecture without an ADR will be asked to add one
before review.

## Code style

- `cargo fmt --all` before submitting.
- `cargo clippy --workspace --all-targets -- -D warnings` must pass.
- Public APIs need rustdoc with at least a one-line summary.
- Prefer additive feature flags over breaking changes.
- Comments explain *why*, not *what*. Code says what.

## Commit conventions

We don't enforce Conventional Commits, but they help. Examples that
work well in this repo:

```
feat(receipts): add Postgres backend
fix(apl): short-circuit `or` evaluating rhs eagerly
docs(adr): clarify stricter-wins merge semantics
chore(ci): cache cargo registry across jobs
```

## Branching and PRs

- Target `main` for PRs.
- One topic per PR. Refactors and feature work go in separate PRs
  whenever possible.
- CI must be green before merge. No skipped checks.
- Squash on merge unless commits are individually meaningful.

## License and the OSS / Enterprise relationship

IAGA Sentinel (the open-source build, this repository) is licensed under
[Business Source License 1.1](LICENSE) with **Change License:
Apache-2.0** and a Change Date of four years from publication. By
submitting a contribution you agree to license your work under the
same terms.

We do not require a CLA. BUSL-1.1 plus the automatic Apache-2.0
conversion baked into the licence is enough to keep the project
durable for community contributors and forks.

**IAGA Sentinel Enterprise** is a separate commercial product built on
the same governance kernel. Enterprise modules live in a separate
repository under a commercial license. Contributions to this repo
flow into both editions automatically when they touch the shared
kernel; the reverse is never true (Enterprise-only code never lands
here).

What this means in practice for contributors:

- A bug fix or feature in `crates/iaga-sentinel-core`, `crates/iaga-sentinel-receipts`,
  `crates/iaga-sentinel-apl`, `crates/iaga-sentinel-reasoning`, or `crates/iaga-sentinel-kernel`
  benefits both OSS and Enterprise users. Welcome.
- We will **never** silently move OSS features behind an Enterprise
  paywall. The promise is documented in
  [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md) §9 and we honour it.
- If you want to discuss building something Enterprise-only (a
  vertical compliance pack, a SIEM connector, a notified-body
  workflow), email `enterprise@iaga.start@gmail.com` rather than
  opening a PR here.

## Security

If you find a security issue that should not be reported publicly,
email `iaga.start@gmail.com` rather than opening a public issue.
We'll respond within a reasonable timeframe and coordinate disclosure.

## Questions

Open a GitHub Discussion or issue. Founder reads everything.
