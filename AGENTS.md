# Repository Guidelines

## Project Structure & Module Organization

This Cargo workspace contains four crates under `crates/`:

- `subconverter-core` owns portable configuration, parsing, conversion, routing, and I/O abstractions.
- `subconverter-cli`, `subconverter-server`, and `subconverter-worker` adapt the core for local commands, Axum HTTP serving, and Cloudflare Workers.

Keep platform-specific filesystem or network behavior out of the core. Shared templates, rules, and example configuration live in `base/`. Integration and golden tests are in `crates/subconverter-core/tests/`; their inputs, manifests, and expected outputs live in `tests/fixtures/`. PowerShell build and smoke-test helpers are under `tools/`. Treat `target/`, `work/`, `outputs/`, and Worker `build/` files as generated artifacts.

## Build, Test, and Development Commands

- `cargo check --workspace` type-checks all crates.
- `cargo build --workspace` builds native workspace targets.
- `cargo run -p subconverter-server` starts the server on the configured port (default `25500`).
- `cargo run -p subconverter-cli -- --target clash --url .\subscription.txt --artifact .\out\clash.yaml` runs one conversion.
- `cargo test --workspace` runs unit, compatibility, and active golden tests.
- `.\tools\verify.ps1` reproduces the main CI checks, including formatting, target checks, Worker validation, and smoke tests; use `-SkipContainer` when Docker is unavailable.

Run `cargo fmt --all` before review; CI enforces `cargo fmt --all -- --check`.

## Coding Style & Naming Conventions

Use standard `rustfmt` output and four-space indentation. Follow Rust naming conventions: `snake_case` for functions and modules, `CamelCase` for types and traits, and `SCREAMING_SNAKE_CASE` for constants. Prefer focused modules and return the shared `Result`/`Error` types from core code. Add dependencies at workspace scope when multiple crates share them.

## Testing Guidelines

Place focused unit tests beside implementation code in `#[cfg(test)]` modules. Add cross-module behavior to `compat.rs`; add stable output comparisons to `golden.rs`. Name tests by behavior, such as `ss_to_clash_smoke_fixture`. No numeric coverage threshold is configured, but behavior changes should include regression tests. Update `tests/fixtures/cases.toml` for active cases. Validate the full manifest with `.\tools\generate-golden.ps1 -Manifest cases.full.toml -ValidateOnly`; only regenerate expected files from a trusted C++ reference executable.

## Commit & Pull Request Guidelines

This checkout has no `.git` directory, so repository-specific history conventions cannot be verified. Use concise, imperative commits with an optional scope, for example `core: preserve subscription headers`. Pull requests should describe compatibility impact, list commands run, link relevant issues, and include representative request/output samples when conversion behavior changes. Never commit tokens, `.env` files, generated artifacts, or real subscription data.
