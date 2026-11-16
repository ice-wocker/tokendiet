# Changelog

## 1.2.0 — 2026-11-16

### Security
- Web visualizer now binds to `127.0.0.1` by default; network binding requires explicit `--host` and prints a warning.
- Repository source retained for the visualizer is scrubbed before it enters the scan summary/API response.
- User-controlled file paths and symbol names render as text nodes rather than HTML; Web API request sizes, JSON types, modes, and formats are validated.
- `.env` and `.env.*` are excluded from prompt bundles by default, while `--audit-secrets` explicitly scans those files (up to 1 MiB).
- Secret detection remains heuristic; it is not a guarantee against credential leakage.

### Compatibility and output correctness
- Added a source-preserving AST stub fallback for Python 3.8, where `ast.unparse` is unavailable.
- `.gitignore` rules are scoped to their directories, support common negation patterns, and no longer hide all dot-directories (including `.github`).
- XML source/path text is escaped; Markdown fences adapt to embedded backticks; JSON format keeps stdout parseable.
- Added `--price-per-million` for custom, explicitly illustrative input-cost estimates.
- Web visualizer now includes per-file selection and recomputes exported prompt totals from selected files.
- Budget estimates now warn when compressed file content still exceeds the requested budget.

### Quality
- Regression suite expanded from 13 to 24 cases across ignore behavior, secret handling, formatters, compatibility, and UI safety.
- CI matrix extended through Python 3.14.
- README and showcase now distinguish measured local samples from assumptions and avoid tokenizer/cost guarantees.
