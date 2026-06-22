# Moved to `/plug-ins`

IAGA Sentinel's in-the-loop integrations now live in the top-level
[`plug-ins/`](../../plug-ins) folder:

- Complete, released plugins: [`plug-ins/codex-plugin/`](../../plug-ins/codex-plugin),
  [`plug-ins/voltagent-plugin/`](../../plug-ins/voltagent-plugin).
- In-progress integrations (copy-paste examples, not yet packaged as standalone
  plugins) are under `plug-ins/<framework>-adapter/` — e.g.
  [`plug-ins/claude-code-adapter/`](../../plug-ins/claude-code-adapter),
  [`plug-ins/langchain-adapter/`](../../plug-ins/langchain-adapter).

See [`plug-ins/README.md`](../../plug-ins/README.md) for the full inventory, the
plugin-vs-adapter distinction, and the shared posture. The reusable client
libraries the adapters build on are in [`sdks/`](../../sdks).
