# ISO 9001:2015 / ISO/IEC 42001:2023 / Agile V Quality Pipeline Skill (`iso9000-agentops` v2.0.0)

Use this skill whenever executing engineering tasks under `/iso9000-agentops`, `/agile-v`, or ISO 9001:2015 / ISO/IEC 42001:2023 quality governance across any repository or testbench.

## Normative Standards Enforced

1. **Agile V (`arXiv:2602.20684`, Christopher Koch)**: *Structured Verification-Driven AI Loops* — enforces a V-model verification loop with Human Gate 1 normative baselines, strict role separation (`Test-Designer` vs `Build-Agent`), bidirectional requirements traceability (`REQ-ID`), and SARIF compliance reporting.
2. **ISO 9001:2015 (QMS)**: Enforces Plan-Do-Check-Act (PDCA), risk-based thinking (FMEA RPN), and documented traceability.
3. **ISO/IEC 42001:2023 (AIMS)**: Artificial Intelligence Management System compliance, requiring structured AI risk assessment, algorithmic bias controls, and robust validation baselines.
4. **P30 Test-Lock Invariants (Claude Code Pre-Commit Gate)**: Strict TDD role separation preventing AI implementers from unilaterally modifying verification tests.

## Strict P30 Test-Lock Invariants

To guarantee valid TDD and independent verification under Agile V:
- **Role Separation**: The `test-designer` writes locked verification tests in `tests/`, while the `implementer` (AI) writes production code in `src/`.
- **Pre-Commit Gate**: AI implementers MUST NEVER modify files inside `tests/` without explicit authorization from the human `test-designer` or the formal requirement baseline changing.
- **Test Integrity**: Test failure must result in modifying production code (`src/`), not relaxing or altering the test assertions.
- **Traceability**: All tests must contain `REQ-*` tags matching the production AST symbols they verify.

## Operational Rules

1. Maintain 100% English-only source, documentation, and commit messages (`0` Cyrillic characters).
2. Enforce dynamic relative paths and never commit personal credentials, local user paths, or ephemeral directories (`.supergraph/`, `.agents-learning/`, `.monitor/`).
3. Route lifecycle hooks through the single-process `agy-golden-stack` / `agy-doctor-mux` dispatcher.
4. Enforce strict Agile V (`arXiv:2602.20684`) role separation (`P30`): `test-designer` writes locked verification tests in `tests/`, and `implementer` writes production code in `src/` without modifying `tests/`.
5. Maintain 100% bidirectional requirements traceability (`REQ-*` tags in both production AST symbols and `test_*` functions) and issue an HMAC-sealed Quality Certificate upon passing the test suite.
