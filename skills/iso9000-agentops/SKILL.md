---
name: iso9000-agentops
description: 6-Echelon ISO 9001:2015, ISO/IEC 42001:2023 & Agile V Quality Pipeline with Bidirectional RTM, ISO 31000 FMEA RPN Engine, HMAC Gate 1 Seals, Self-Grading Bias Guard, Planarian Rollback, and SARIF 2.1.0 Quality Certificates.
---

# ISO 9001:2015 / ISO/IEC 42001:2023 / Agile V Quality Pipeline Skill (`iso9000-agentops` v2.0.0)

Use this skill whenever executing engineering tasks under `/iso9000-agentops`, `/agile-v`, or ISO 9001:2015 / ISO/IEC 42001:2023 quality governance across any repository or testbench.

## Normative Standards Enforced

1. **Agile V (`arXiv:2602.20684`, Christopher Koch)**: *Structured Verification-Driven AI Loops* — enforces a V-model verification loop with Human Gate 1 normative baselines, strict role separation (`Test-Designer` vs `Build-Agent`), bidirectional requirements traceability (`REQ-ID <-> AST Code Symbol <-> Verification Test <-> EvidenceUnit`), and Human Gate 2 acceptance.
2. **ISO 9001:2015 (Quality Management Systems)**: Clauses 6.1 (Risk-based thinking), 7.5 (Documented information), 8.3 (Design & development traceability), 8.5 (Controlled production), 9.1 (Independent verification), and 10.2 (Nonconformity & CAPA).
3. **ISO/IEC 42001:2023 (AI Management System — Annex A)**: Statement of Applicability (SoA) across controls `A.6.2.2`, `A.6.2.4`, `A.7.4`, `A.8.3`, `A.9.3`, and `A.10.2`.
4. **ISO 31000 / IEC 60812 FMEA**: Quantitative Failure Mode and Effects Analysis (`RPN = Severity * Occurrence * Detection`, range `1..1000`, `S >= 9 -> L4`).
5. **W3C PROV-DM & RFC 6962 Merkle Audit Trees**: Cryptographic SHA-256 hash chains and binary Merkle trees (`0x00` leaf / `0x01` internal node) with $O(\log N)$ inclusion proofs.
6. **OASIS SARIF 2.1.0**: Standardized Static Analysis Results Interchange Format reports and signed SVG compliance badges.

---

## Step-by-Step 6-Echelon Execution Protocol (`v2.0.0`)

### Echelon 1: Normative Planning, FMEA Risk Assessment & Frozen Baseline (`[ROLE: ARCHITECT]`)

1. **Decompose Requirements & Initialize Frozen Baseline**:
   Assign explicit `REQ-*` identifiers (`REQ-001`, `REQ-002`, ...) to every functional and non-functional requirement:
   ```bash
   python -m iso9000_agentops.cli --workspace . init-baseline "(REQ-001) First requirement; (REQ-002) Second requirement" --risk L2 --offline
   ```
2. **Approve Human Gate 1 (`HMAC-SHA256` Cryptographic Seal)**:
   For `L2-L4` tasks, write the 64-character HMAC-SHA256 seal into `.supergraph/frozen_baseline.yaml`:
   ```bash
   python -m iso9000_agentops.cli --workspace . approve-gate1
   ```
3. **Execute ISO 31000 FMEA & ISO/IEC 42001:2023 Statement of Applicability**:
   Evaluate failure modes (`RPN = S * O * D`) and generate `.supergraph/fmea_42001_report.json`:
   ```bash
   python -m iso9000_agentops.cli --workspace . fmea
   ```
   *(Or pass custom failure modes via `--modes-json '[{"id":"FM-01","name":"Schema drift","severity":6,"occurrence":3,"detection":4}]'`)*

---

### Echelon 2 & 3: Strict Agile V Role Separation (`P30` Self-Grading Bias Guard)

1. **Phase 1 — `TEST_DESIGN` (`[ROLE: TEST-DESIGNER / VERIFIER]`)**:
   - Transition state machine to `TEST_DESIGN`:
     ```bash
     python -m iso9000_agentops.cli --workspace . set-phase TEST_DESIGN --role test-designer --emit-brief
     ```
   - Author unit and Hypothesis property-based tests strictly inside `tests/`.
   - **Traceability Rule**: Every test function (`test_*`) MUST reference its target `REQ-*` ID via docstring (`"""REQ-001: ..."""`), decorator (`@pytest.mark.req("REQ-001")`), or inline comment (`# REQ-001`) so `extract_test_req_links` links 100% of tests.
   - Lock the SHA-256 hashes of all files in `tests/`.

2. **Phase 2 — `SYNTHESIS` (`[ROLE: IMPLEMENTER / BUILD-AGENT]`)**:
   - Transition state machine to `SYNTHESIS` and save a Planarian statepoint checkpoint:
     ```bash
     python -m iso9000_agentops.cli --workspace . set-phase SYNTHESIS --role implementer --emit-brief
     python -m iso9000_agentops.cli --workspace . checkpoint --label pre_synthesis
     ```
   - Implement production modules strictly inside `src/` (or package directory).
   - **Self-Grading Bias Prohibition (`P30`)**: The `implementer` role is **strictly forbidden** from modifying any file in `tests/` or `.supergraph/frozen_baseline.yaml`.
   - **Traceability & Anti-Gold-Plating Rule**: Every public class, function, and method in production code MUST include its corresponding `REQ-*` ID in its docstring (`"""... (REQ-001)."""`) so `extract_code_req_links` verifies 0 unimplemented requirements and 0 gold-plated symbols.
   - **SSE Stream Chunking Guard (`<= 180` lines / `<= 3,500` output tokens per `write_file` call)**: Never attempt to emit a monolithic multi-hundred-line file or multi-module course in a single `write_file` call (which exceeds the 240-second `streamGenerateContent?alt=sse` timeout and resets the prompt cache). Split large deliverables into modular files or sequential `write_file(..., Append=True)` chunks of `<= 180` lines each.

---

### Echelon 4: Swiss Cheese Guardrails & Planarian Asymmetric Rollback

- `evaluate_pre_tool_guard` intercepts both direct file writes and shell commands (`>`, `sed`, `Set-Content`, `Out-File`) attempting to mutate `tests/` during `SYNTHESIS` or unsealed `L2-L4` baselines.
- Three consecutive verification failures automatically back up work-in-progress to `.supergraph/rollback_backups/` and restore the clean `.supergraph/statepoints/<node_id>/` snapshot.

---

### Echelon 5: Independent Verification, Bidirectional RTM, Live Stress Test & Quality Certificate

1. **Run Independent Verification Oracle (`W3C PROV-DM`)**:
   ```bash
   python -m iso9000_agentops.cli --workspace . verify --cmd "python -m pytest tests -v"
   ```
2. **Build Bidirectional Agile V Requirements Traceability Matrix (`RTM`)**:
   ```bash
   python -m iso9000_agentops.cli --workspace . rtm --reqs REQ-001,REQ-002 --src src --tests tests
   ```
   Verify `compliant: true`, `coverage_ratio: 1.0`, `orphan_requirements: []`, `unimplemented_requirements: []`, and `gold_plated_symbols: []`.
3. **Execute Mandatory Live Real-Task Stress Test (`REQ-ARCH-05`)**:
   Execute the newly built feature on a real workspace/task target and verify empirical output before advancing.
4. **Issue Cryptographic Quality Certificate, SVG Badge & OASIS SARIF 2.1.0 Report**:
   ```bash
   python -m iso9000_agentops.cli --workspace . certify --reqs REQ-001,REQ-002 --src src --tests tests
   ```
   Writes:
   - `.supergraph/quality_certificate.json` (`status: "CERTIFIED"`, 64-char `certificate_signature`)
   - `.supergraph/compliance_badge.svg`
   - `.supergraph/compliance_report.sarif.json` (OASIS SARIF 2.1.0)

---

### Echelon 6: Human Gate 2, Senior Diff Tour & CAPA Consolidation

1. **Consolidate ExpeL Rules & Extract Trace2Skill SOP**:
   ```bash
   python -m iso9000_agentops.cli --workspace . capa --trace2skill --skill-name verified-sop --offline
   ```
2. **5-Gate Open-Source Release Audit (if publishing to Git)**:
   ```bash
   python -m iso9000_agentops.cli --workspace . audit-repo
   ```
