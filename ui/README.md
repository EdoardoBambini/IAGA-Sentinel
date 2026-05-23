# IAGA Sentinel UI

Official frontend for IAGA Sentinel. Inspired by the Jarvis neural interface and adapted to IAGA Sentinel branding.

Starting with 1.0, this folder is the canonical UI: it can be embedded directly
into the `iaga-sentinel` / `iaga` binary (see the `ui-embed` feature flag in
`crates/iaga-sentinel-core/Cargo.toml`) and served on `/ui` by `iaga serve`. Until the
embed wiring lands in a later milestone, the app also runs as a standalone Vite
dev server.

## What It Is

- same neural-network aesthetic and motion language as the original visual
- IAGA Sentinel specific labels, metrics, and messaging
- built as a separate Vite app so it can evolve without touching the runtime code
- production build (`ui/dist/`) is embedded in the Rust binary when compiled
  with `--features ui-embed`

## Run (dev)

```bash
cd ui
npm install
npm run dev
```

## Build (for embedding)

```bash
cd ui
npm run build
```

This produces `ui/dist/`. From the repo root:

```bash
cargo build -p iaga-sentinel-core --features ui-embed
```

The bundled assets become reachable via `iaga_sentinel::ui_embed::UiAssets`
(route wiring lands in a later milestone).

## Migration Note

This folder was called `visual/` in 0.4.0. The rename is tracked in
`MIGRATION.md` at the repo root.
