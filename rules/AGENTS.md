# ISO 9001:2015 / ISO/IEC 42001:2023 / Agile V Operational Rules (`v2.0.0`)

1. Maintain 100% English-only source, documentation, and commit messages (`0` Cyrillic characters).
2. Enforce dynamic relative paths and never commit personal credentials, local user paths, or ephemeral directories (`.supergraph/`, `.agents-learning/`, `.monitor/`).
3. Route lifecycle hooks through the single-process `agy-golden-stack` / `agy-doctor-mux` dispatcher.
4. Enforce strict Agile V (`arXiv:2602.20684`) role separation (`P30`): `test-designer` writes locked verification tests in `tests/`, and `implementer` writes production code in `src/` without modifying `tests/`.
5. Maintain 100% bidirectional requirements traceability (`REQ-*` tags in both production AST symbols and `test_*` functions) and issue an HMAC-SHA256 quality certificate + OASIS SARIF 2.1.0 report (`certify`) upon verification.
6. Execute a mandatory Live Real-Task Stress Test (`REQ-ARCH-05`) on real production targets before advancing to the next roadmap step or architecture tier (`L1 -> L2 -> L3 -> L4`).
7. Enforce the SSE Stream Chunking Guard (`<= 180` lines or `<= 3,500` output tokens per `write_file` call; split large deliverables into modular files or sequential `write_file(..., Append=True)` chunks) so tool calls never hit the 240-second Cloud Code SSE timeout (`streamGenerateContent?alt=sse: EOF`).
