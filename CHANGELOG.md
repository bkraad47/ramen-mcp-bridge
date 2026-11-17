# Changelog

## 1.0.0 — 2026-11-17

The bridge for Ramen 1.0.0. Everything from the unreleased 0.4.0, 0.5.0 and 0.6.0 lines ships here (PyPI went from
0.3.0 straight to 1.0.0).

- **TLS by default** (Ramen D86): the bridge always dials TLS and verifies the server; `--insecure` is explicit,
  warns, and is refused next to `--tls` / `--ca`. `--ca` replaces the trust store for that connection.
- **Policy bundle** kept at `~/.ramen`: telemetry, evals, SkillSpector, group LLM configs and guardrails versions sent
  on every gated call (`params._meta["io.ramen/…"]`), so a group's Required policies pass through the bridge;
  `ramen-mcp-bridge policy show|check|remove`.
- **Telemetry through Ramen** (OTLP to the console's ingest, `ramen.user` on every span).
- **Group LLM configs**: accepted per person and version, written into the client's config files (Claude Code,
  Cursor, Codex, …) between marked blocks; removed on `policy remove`.
- **SkillSpector**: the group's scan policy and a local baseline; skills over MCP — `skills list`, `skills install
  <name> [--dir]` from `skill://` resources.
- **Guardrails**: the group's NeMo rails also run locally (`nemo` extra), including the hallucination judge through
  the console's judge proxy (provider keys never reach the client).

## 0.3.0

OAuth sign-in through the console (`--oauth`), group keys, stdio ↔ `ramen.v1.Mcp/Call`.
