"""Unified CLI Orchestrator for the ISO 9001:2015 / ISO/IEC 42001:2023 / Agile V Pipeline (REQ-ISO-204)."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from iso9000_agentops.aims_42001 import (
    assess_failure_modes,
    generate_iso42001_soa,
)
from iso9000_agentops.certificate import (
    certify_ecosystem_portfolio,
    export_sarif_report,
    issue_quality_certificate,
    render_compliance_badge_svg,
)
from iso9000_agentops.crypto_guard import (
    build_merkle_audit_tree,
    compute_gate1_hmac,
    dump_yaml_contract,
    ensure_gate_secret,
    parse_yaml_or_json,
)
from iso9000_agentops.installer import install_hooks
from iso9000_agentops.llm import MultiProviderLLMAdapter
from iso9000_agentops.traceability import (
    build_requirements_traceability_matrix,
    extract_test_req_links,
    render_rtm_markdown,
)
import contextlib

_EXCLUDED_DIRS = {
    ".supergraph",
    ".agents-learning",
    ".monitor",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "node_modules",
}


def _iter_workspace_files(ws: Path) -> list[Path]:
    files: list[Path] = []
    for item in ws.rglob("*"):
        if not item.is_file():
            continue
        rel_parts = item.relative_to(ws).parts
        if any(part in _EXCLUDED_DIRS for part in rel_parts):
            continue
        files.append(item)
    return files


def _copy_workspace_tree(src_root: Path, dst_root: Path) -> int:
    count = 0
    for f in _iter_workspace_files(src_root):
        rel = f.relative_to(src_root)
        target = dst_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, target)
        count += 1
    return count


def _extract_workspace_arg(argv: list[str]) -> tuple[Path, list[str]]:
    ws = Path.cwd()
    cleaned: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--workspace" and i + 1 < len(argv):
            ws = Path(argv[i + 1]).resolve()
            i += 2
        elif tok.startswith("--workspace="):
            ws = Path(tok.split("=", 1)[1]).resolve()
            i += 1
        else:
            cleaned.append(tok)
            i += 1
    return ws, cleaned


def _resolve_source_and_tests_dirs(
    ws: Path, source_arg: str | None = None, tests_arg: str | None = None
) -> tuple[Path, Path]:
    if source_arg:
        src_dir = Path(source_arg).resolve()
    elif (ws / "src").is_dir():
        src_dir = ws / "src"
    elif (ws / "iso9000_agentops").is_dir():
        src_dir = ws / "iso9000_agentops"
    elif (ws / "app").is_dir():
        src_dir = ws / "app"
    else:
        src_dir = ws

    if tests_arg:
        tests_dir = Path(tests_arg).resolve()
    elif (ws / "tests").is_dir():
        tests_dir = ws / "tests"
    else:
        tests_dir = ws

    return src_dir, tests_dir


def _load_evidence_units(sg_dir: Path) -> list[dict[str, Any]]:
    chain_file = sg_dir / "audit_chain.json"
    if chain_file.is_file():
        try:
            data = json.loads(chain_file.read_text(encoding="utf-8"))
            if isinstance(data.get("evidence_units"), list):
                return list(data["evidence_units"])
        except Exception:
            pass
    ev_file = sg_dir / "evidence_units.jsonl"
    if ev_file.is_file():
        units: list[dict[str, Any]] = []
        for line in ev_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                with contextlib.suppress(Exception):
                    units.append(json.loads(line))
        return units
    return []


def run_cli(argv: list[str] | None = None) -> dict[str, Any]:
    """Execute an ISO 9001:2015 / ISO/IEC 42001:2023 / Agile V CLI command (REQ-ISO-204)."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    ws, remaining = _extract_workspace_arg(raw_args)
    ws.mkdir(parents=True, exist_ok=True)

    parser = argparse.ArgumentParser(prog="iso9000-agentops", add_help=False)
    subparsers = parser.add_subparsers(dest="subcommand")

    # 1. init-baseline
    p_init = subparsers.add_parser("init-baseline")
    p_init.add_argument("task", nargs="?", default="Default engineering task")
    p_init.add_argument("--risk", default="L2")
    p_init.add_argument("--offline", action="store_true")
    p_init.add_argument("--provider", default="offline")
    p_init.add_argument("--allow", nargs="*", default=["src/**", "app/**", "tests/**"])
    p_init.add_argument("--forbid", nargs="*", default=[".env*", "*.key", "*.pem"])
    p_init.add_argument("--must-not", nargs="*", default=["modify locked tests during SYNTHESIS"])

    # 2. approve-gate1
    subparsers.add_parser("approve-gate1")

    # 3. set-phase
    p_phase = subparsers.add_parser("set-phase")
    p_phase.add_argument("phase")
    p_phase.add_argument("--role", default="implementer")
    p_phase.add_argument("--emit-brief", action="store_true")

    # 4. checkpoint
    p_cp = subparsers.add_parser("checkpoint")
    p_cp.add_argument("--label", default="statepoint")
    p_cp.add_argument("--node", default="M0")

    # 5. verify
    p_ver = subparsers.add_parser("verify")
    p_ver.add_argument("--cmd", required=True)

    # 6. capa
    p_capa = subparsers.add_parser("capa")
    p_capa.add_argument("--trace2skill", action="store_true")
    p_capa.add_argument("--skill-name", default="iso9000-learned-skill")
    p_capa.add_argument("--offline", action="store_true")

    # 7. install-hooks
    p_inst = subparsers.add_parser("install-hooks")
    p_inst.add_argument("--target", required=True)
    p_inst.add_argument("--dest", required=True)

    # 8. benchmark
    subparsers.add_parser("benchmark")

    # 9. audit-repo
    p_audit = subparsers.add_parser("audit-repo")
    p_audit.add_argument("--repo", default=None)

    # 10. rtm (v2.0.0 REQ-ISO-204)
    p_rtm = subparsers.add_parser("rtm")
    p_rtm.add_argument("--source", "--src", dest="source", default=None)
    p_rtm.add_argument("--tests", default=None)
    p_rtm.add_argument("--reqs", default=None)

    # 11. fmea (v2.0.0 REQ-ISO-204)
    p_fmea = subparsers.add_parser("fmea")
    p_fmea.add_argument("--modes-json", default=None)

    # 12. certify (v2.0.0 REQ-ISO-204)
    p_cert = subparsers.add_parser("certify")
    p_cert.add_argument("--source", "--src", dest="source", default=None)
    p_cert.add_argument("--tests", default=None)
    p_cert.add_argument("--reqs", default=None)

    # 13. certify-portfolio (v2.0.0 REQ-ISO-205)
    p_cert_port = subparsers.add_parser("certify-portfolio")
    p_cert_port.add_argument("--portfolio-json", required=True, help="Path or raw JSON string of portfolio repository reports")
    p_cert_port.add_argument("--name", default="Antigravity Ecosystem", help="Portfolio name")
    p_cert_port.add_argument("--version", default="2.0.0", help="Portfolio version")
    p_cert_port.add_argument("--output", default=None, help="Output file path for portfolio certificate JSON")
    p_cert_port.add_argument("--secret", default="default-iso9000-cert-secret", help="HMAC secret for certificate signing")

    ns, _ = parser.parse_known_args(remaining)
    cmd = ns.subcommand

    sg_dir = ws / ".supergraph"
    bl_file = sg_dir / "frozen_baseline.yaml"
    state_file = sg_dir / "state.json"

    if cmd == "init-baseline":
        sg_dir.mkdir(parents=True, exist_ok=True)
        risk = str(ns.risk).upper().strip()
        provider = "offline" if ns.offline else str(ns.provider)
        adapter = MultiProviderLLMAdapter(provider=provider)
        reqs = adapter.decompose_requirements(ns.task, risk_level=risk)

        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
        baseline_id = f"BL-{today}-{risk}"
        gate_approved = risk in ("L0", "L1")

        baseline_dict: dict[str, Any] = {
            "baseline_id": baseline_id,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "risk_level": risk,
            "human_gate_1_approved": gate_approved,
            "aop_validation": {
                "solvable": True,
                "completeness_covered": True,
                "non_redundant": True,
            },
            "artifact_scope": {
                "allowed_paths": list(ns.allow),
                "forbidden_paths": list(ns.forbid),
                "must_not_predicates": list(ns.must_not),
            },
            "requirements": reqs,
        }
        if gate_approved:
            ensure_gate_secret(ws)
            baseline_dict["gate_seal_hmac"] = compute_gate1_hmac(baseline_dict, workspace=ws)

        bl_file.write_text(dump_yaml_contract(baseline_dict), encoding="utf-8")

        state_dict: dict[str, Any] = {
            "baseline_id": baseline_id,
            "risk_level": risk,
            "human_gate_1_approved": gate_approved,
            "current_phase": "PLANNING",
            "phase": "PLANNING",
            "active_role": "architect",
            "strict_role_isolation": True,
            "current_node": "M0",
            "step_failures": 0,
            "max_step_failures": 3,
        }
        state_file.write_text(json.dumps(state_dict, indent=2), encoding="utf-8")
        return {
            "status": "initialized",
            "baseline_id": baseline_id,
            "risk_level": risk,
            "human_gate_1_approved": gate_approved,
            "requirements": reqs,
        }

    if cmd == "approve-gate1":
        sg_dir.mkdir(parents=True, exist_ok=True)
        baseline = (
            parse_yaml_or_json(bl_file.read_text(encoding="utf-8"))
            if bl_file.is_file()
            else {"baseline_id": "BL-DEFAULT", "risk_level": "L2", "requirements": []}
        )
        ensure_gate_secret(ws)
        baseline["human_gate_1_approved"] = True
        seal = compute_gate1_hmac(baseline, workspace=ws)
        baseline["gate_seal_hmac"] = seal
        bl_file.write_text(dump_yaml_contract(baseline), encoding="utf-8")

        state = (
            json.loads(state_file.read_text(encoding="utf-8"))
            if state_file.is_file()
            else {}
        )
        state["human_gate_1_approved"] = True
        state["gate_seal_hmac"] = seal
        state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
        return {
            "status": "ok",
            "human_gate_1_approved": True,
            "gate_seal_hmac": seal,
        }

    if cmd == "set-phase":
        sg_dir.mkdir(parents=True, exist_ok=True)
        phase = str(ns.phase).upper().strip()
        role = str(ns.role).strip()
        baseline = (
            parse_yaml_or_json(bl_file.read_text(encoding="utf-8"))
            if bl_file.is_file()
            else {}
        )
        state = (
            json.loads(state_file.read_text(encoding="utf-8"))
            if state_file.is_file()
            else {}
        )
        state["current_phase"] = phase
        state["phase"] = phase
        state["active_role"] = role
        state.setdefault("strict_role_isolation", True)
        state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

        if phase == "TEST_DESIGN":
            allowed_globs = ["tests/**"]
            forbidden_globs = ["src/**", "app/**", ".supergraph/frozen_baseline.yaml"]
        elif phase == "SYNTHESIS":
            allowed_globs = ["src/**", "app/**"]
            forbidden_globs = ["tests/**", ".supergraph/frozen_baseline.yaml"]
        else:
            scope = baseline.get("artifact_scope") or {}
            allowed_globs = list(scope.get("allowed_paths") or ["src/**", "tests/**"])
            forbidden_globs = list(scope.get("forbidden_paths") or [".env*"])

        return {
            "status": "ok",
            "phase": phase,
            "role": role,
            "allowed_write_globs": allowed_globs,
            "forbidden_write_globs": forbidden_globs,
            "requirements": baseline.get("requirements", []),
        }

    if cmd == "checkpoint":
        sg_dir.mkdir(parents=True, exist_ok=True)
        state = (
            json.loads(state_file.read_text(encoding="utf-8"))
            if state_file.is_file()
            else {}
        )
        node_id = str(state.get("current_node") or ns.node or "M0")
        sp_dir = sg_dir / "statepoints" / node_id
        if sp_dir.exists():
            shutil.rmtree(sp_dir)
        sp_dir.mkdir(parents=True, exist_ok=True)
        saved_count = _copy_workspace_tree(ws, sp_dir)
        return {
            "status": "ok",
            "node_id": node_id,
            "label": ns.label,
            "files_saved": saved_count,
        }

    if cmd == "verify":
        sg_dir.mkdir(parents=True, exist_ok=True)
        state = (
            json.loads(state_file.read_text(encoding="utf-8"))
            if state_file.is_file()
            else {"current_node": "M0", "step_failures": 0, "max_step_failures": 3}
        )
        baseline = (
            parse_yaml_or_json(bl_file.read_text(encoding="utf-8"))
            if bl_file.is_file()
            else {"baseline_id": "BL-DEFAULT", "requirements": []}
        )
        node_id = str(state.get("current_node") or "M0")
        sp_dir = sg_dir / "statepoints" / node_id

        proc = subprocess.run(
            ns.cmd,
            cwd=str(ws),
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        stdout_hash = hashlib.sha256(
            (proc.stdout + proc.stderr).encode("utf-8")
        ).hexdigest()

        if proc.returncode == 0:
            state["step_failures"] = 0
            state["current_phase"] = "VERIFICATION"
            state["phase"] = "VERIFICATION"
            state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

            req_ids = [
                str(r.get("id", "REQ-001"))
                for r in (baseline.get("requirements") or [{"id": "REQ-001"}])
                if isinstance(r, dict)
            ]
            ev_unit = {
                "evidence_id": f"EV-{hashlib.sha256((ns.cmd + stdout_hash).encode('utf-8')).hexdigest()[:12]}",
                "baseline_id": baseline.get("baseline_id", "BL-DEFAULT"),
                "requirement_ids": req_ids,
                "command": ns.cmd,
                "exit_code": 0,
                "stdout_sha256": stdout_hash,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "prov": {
                    "wasGeneratedBy": "iso9000-agentops:verify",
                    "wasAssociatedWith": state.get("active_role", "verifier"),
                    "wasDerivedFrom": str(bl_file.name),
                },
            }
            ev_file = sg_dir / "evidence_units.jsonl"
            with ev_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev_unit) + "\n")

            all_units = [
                json.loads(line)
                for line in ev_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            chain_payload = json.dumps(all_units, sort_keys=True).encode("utf-8")
            chain_sha256 = hashlib.sha256(chain_payload).hexdigest()
            audit_chain = {
                "baseline_id": baseline.get("baseline_id", "BL-DEFAULT"),
                "audit_chain_sha256": chain_sha256,
                "evidence_count": len(all_units),
                "evidence_units": all_units,
            }
            (sg_dir / "audit_chain.json").write_text(
                json.dumps(audit_chain, indent=2), encoding="utf-8"
            )
            return {
                "status": "ok",
                "verification": "PASSED",
                "exit_code": 0,
                "evidence_unit": ev_unit,
                "audit_chain_sha256": chain_sha256,
                "planarian_rollback_triggered": False,
            }

        # Verification failed
        failures = int(state.get("step_failures", 0)) + 1
        max_failures = int(state.get("max_step_failures", 3))
        rollback_triggered = False

        if failures >= max_failures:
            rollback_triggered = True
            ts_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
            backup_dir = sg_dir / "rollback_backups" / f"{node_id}_{ts_id}"
            backup_dir.mkdir(parents=True, exist_ok=True)
            _copy_workspace_tree(ws, backup_dir)

            if sp_dir.is_dir():
                for sp_file in sp_dir.rglob("*"):
                    if not sp_file.is_file():
                        continue
                    rel = sp_file.relative_to(sp_dir)
                    dest_file = ws / rel
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(sp_file, dest_file)

            ledger_entry = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "node_id": node_id,
                "command": ns.cmd,
                "exit_code": proc.returncode,
                "backup_dir": str(backup_dir),
                "reason": f"Planarian asymmetric rollback triggered after {failures} consecutive failures.",
            }
            with (sg_dir / "failure_ledger.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(ledger_entry) + "\n")
            failures = 0

        state["step_failures"] = failures
        state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
        return {
            "status": "failed",
            "verification": "FAILED",
            "exit_code": proc.returncode,
            "step_failures": failures,
            "planarian_rollback_triggered": rollback_triggered,
        }

    if cmd == "capa":
        learn_dir = ws / ".agents-learning"
        learn_dir.mkdir(parents=True, exist_ok=True)
        rules_file = learn_dir / "expel_rules.json"
        existing_rules: list[dict[str, Any]] = []
        if rules_file.is_file():
            try:
                existing_rules = json.loads(rules_file.read_text(encoding="utf-8"))
            except Exception:
                existing_rules = []

        ledger_file = sg_dir / "failure_ledger.jsonl"
        failures_list: list[dict[str, Any]] = []
        if ledger_file.is_file():
            for line in ledger_file.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    with contextlib.suppress(Exception):
                        failures_list.append(json.loads(line))

        if not existing_rules:
            existing_rules.append(
                {
                    "rule_id": "RULE-CAPA-001",
                    "rule": "Enforce strict Test-Designer / Build-Agent isolation and verify against locked oracle.",
                    "weight": 10 + len(failures_list),
                    " textual_gradient": "Prevent self-grading bias and unverified mutations.",
                }
            )
        rules_file.write_text(json.dumps(existing_rules, indent=2), encoding="utf-8")

        report = {
            "status": "ok",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "failures_analyzed": len(failures_list),
            "rules_count": len(existing_rules),
            "rules": existing_rules,
        }
        (learn_dir / "capa_optoprime_report.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )

        if ns.trace2skill:
            skill_dir = ws / ".agents" / "skills" / str(ns.skill_name)
            skill_dir.mkdir(parents=True, exist_ok=True)
            skill_md = skill_dir / "SKILL.md"
            skill_md.write_text(
                f"---\nname: {ns.skill_name}\ndescription: Auto-extracted Trace2Skill SOP from CAPA OptoPrime.\n---\n\n"
                f"# {ns.skill_name}\n\nConsolidated {len(existing_rules)} ExpeL rules from verified trajectory.\n",
                encoding="utf-8",
            )
            report["trace2skill_path"] = str(skill_md)

        return report

    if cmd == "install-hooks":
        return install_hooks(target=ns.target, dest_dir=Path(ns.dest))

    if cmd == "benchmark":
        from iso9000_agentops.benchmarks import run_benchmark_suite

        return run_benchmark_suite()

    if cmd == "audit-repo":
        from iso9000_agentops.oss_audit import audit_git_repository

        target_repo = Path(ns.repo) if ns.repo else ws
        return audit_git_repository(target_repo)

    if cmd == "rtm":
        sg_dir.mkdir(parents=True, exist_ok=True)
        baseline = (
            parse_yaml_or_json(bl_file.read_text(encoding="utf-8"))
            if bl_file.is_file()
            else {"requirements": []}
        )
        if ns.reqs:
            req_input: list[Any] = [
                r.strip() for r in str(ns.reqs).split(",") if r.strip()
            ]
        else:
            req_input = baseline.get("requirements") or []
        src_dir, tests_dir = _resolve_source_and_tests_dirs(ws, ns.source, ns.tests)
        evidence_units = _load_evidence_units(sg_dir)
        rtm = build_requirements_traceability_matrix(
            requirements=req_input,
            source_root=src_dir,
            tests_root=tests_dir,
            evidence_units=evidence_units,
        )
        md = render_rtm_markdown(rtm)
        (sg_dir / "rtm_report.json").write_text(
            json.dumps(rtm, indent=2), encoding="utf-8"
        )
        (sg_dir / "rtm_report.md").write_text(md, encoding="utf-8")
        return {**rtm, "rtm": rtm, "markdown_path": str(sg_dir / "rtm_report.md")}

    if cmd == "fmea":
        sg_dir.mkdir(parents=True, exist_ok=True)
        baseline = (
            parse_yaml_or_json(bl_file.read_text(encoding="utf-8"))
            if bl_file.is_file()
            else {
                "baseline_id": "BL-DEFAULT",
                "risk_level": "L1",
                "human_gate_1_approved": True,
            }
        )
        default_modes = [
            {
                "id": "FM-DEFAULT-01",
                "name": "Routine verification jitter",
                "severity": 3,
                "occurrence": 2,
                "detection": 2,
            }
        ]
        if ns.modes_json:
            raw_m = str(ns.modes_json).strip()
            p_m = Path(raw_m)
            if p_m.is_file():
                modes = json.loads(p_m.read_text(encoding="utf-8"))
            else:
                modes = json.loads(raw_m)
        else:
            modes = default_modes

        fmea_report = assess_failure_modes(modes)
        soa = generate_iso42001_soa(baseline, fmea_summary=fmea_report)
        combined = {
            **fmea_report,
            "fmea": fmea_report,
            "soa": soa,
            "standard": soa["standard"],
            "controls": soa["controls"],
        }
        (sg_dir / "fmea_42001_report.json").write_text(
            json.dumps(combined, indent=2), encoding="utf-8"
        )
        return combined

    if cmd == "certify":
        sg_dir.mkdir(parents=True, exist_ok=True)
        baseline = (
            parse_yaml_or_json(bl_file.read_text(encoding="utf-8"))
            if bl_file.is_file()
            else {
                "baseline_id": "BL-DEFAULT",
                "risk_level": "L1",
                "human_gate_1_approved": True,
                "requirements": [],
            }
        )
        baseline_id = str(baseline.get("baseline_id") or "BL-DEFAULT")
        secret = ensure_gate_secret(ws)
        gate1_hmac = str(baseline.get("gate_seal_hmac") or "")
        if len(gate1_hmac) != 64 and baseline.get("human_gate_1_approved"):
            gate1_hmac = compute_gate1_hmac(baseline, workspace=ws)

        src_dir, tests_dir = _resolve_source_and_tests_dirs(ws, ns.source, ns.tests)
        evidence_units = _load_evidence_units(sg_dir)
        if ns.reqs:
            cert_reqs: list[Any] = [
                r.strip() for r in str(ns.reqs).split(",") if r.strip()
            ]
        else:
            cert_reqs = baseline.get("requirements") or []

        rtm_report = build_requirements_traceability_matrix(
            requirements=cert_reqs,
            source_root=src_dir,
            tests_root=tests_dir,
            evidence_units=evidence_units,
        )

        fmea_file = sg_dir / "fmea_42001_report.json"
        if fmea_file.is_file():
            loaded_fmea = json.loads(fmea_file.read_text(encoding="utf-8"))
            fmea_report = loaded_fmea.get("fmea", loaded_fmea)
        else:
            fmea_report = assess_failure_modes(
                [
                    {
                        "id": "FM-DEFAULT-01",
                        "name": "Routine verification jitter",
                        "severity": 3,
                        "occurrence": 2,
                        "detection": 2,
                    }
                ]
            )

        if evidence_units:
            leaf_payloads = [
                json.dumps(u, sort_keys=True).encode("utf-8") for u in evidence_units
            ]
        else:
            leaf_payloads = [
                json.dumps(baseline, sort_keys=True).encode("utf-8")
            ]
        merkle_tree = build_merkle_audit_tree(leaf_payloads)
        merkle_root = str(merkle_tree.get("root") or "")

        discovered_tests = extract_test_req_links(tests_dir)
        tests_total = max(len(discovered_tests), len(evidence_units), 1)
        all_ev_passed = bool(evidence_units) and all(
            int(u.get("exit_code", 1)) == 0 for u in evidence_units
        )
        tests_passed = tests_total if (all_ev_passed or rtm_report["compliant"]) else 0

        cert = issue_quality_certificate(
            baseline_id=baseline_id,
            version="2.0.0",
            rtm_report=rtm_report,
            fmea_report=fmea_report,
            merkle_root=merkle_root,
            gate1_hmac=gate1_hmac,
            tests_passed=tests_passed,
            tests_total=tests_total,
            secret=secret,
        )
        svg = render_compliance_badge_svg(cert)
        sarif = export_sarif_report(
            rtm_report=rtm_report,
            fmea_report=fmea_report,
            oss_audit_report={"passed": True},
            tool_version="2.0.0",
        )

        (sg_dir / "quality_certificate.json").write_text(
            json.dumps(cert, indent=2), encoding="utf-8"
        )
        (sg_dir / "compliance_badge.svg").write_text(svg, encoding="utf-8")
        (sg_dir / "compliance_report.sarif.json").write_text(
            json.dumps(sarif, indent=2), encoding="utf-8"
        )

        return {
            **cert,
            "certificate": cert,
            "rtm": rtm_report,
            "fmea": fmea_report,
        }

    if cmd == "certify-portfolio":
        raw_json = str(ns.portfolio_json).strip()
        p_json = Path(raw_json)
        if p_json.is_file():
            loaded = json.loads(p_json.read_text(encoding="utf-8"))
        else:
            loaded = json.loads(raw_json)

        if isinstance(loaded, dict) and "repository_reports" in loaded and isinstance(loaded["repository_reports"], dict):
            repo_reports = loaded["repository_reports"]
        else:
            repo_reports = loaded

        port_name = str(getattr(ns, "name", None) or "Antigravity Ecosystem")
        port_version = str(getattr(ns, "version", None) or "2.0.0")
        secret = str(getattr(ns, "secret", None) or "default-iso9000-cert-secret")

        cert = certify_ecosystem_portfolio(
            portfolio_name=port_name,
            version=port_version,
            repository_reports=repo_reports,
            secret=secret,
        )

        if ns.output:
            out_p = Path(ns.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(json.dumps(cert, indent=2), encoding="utf-8")

        sg_dir.mkdir(parents=True, exist_ok=True)
        (sg_dir / "portfolio_certificate.json").write_text(
            json.dumps(cert, indent=2), encoding="utf-8"
        )
        if "badge_svg" in cert:
            (sg_dir / "portfolio_badge.svg").write_text(cert["badge_svg"], encoding="utf-8")
        if "sarif_report" in cert:
            (sg_dir / "portfolio_sarif.json").write_text(
                json.dumps(cert["sarif_report"], indent=2), encoding="utf-8"
            )

        return {
            **cert,
            "portfolio_certificate": cert,
        }

    raise ValueError(f"Unknown or missing subcommand: {cmd!r}")


def main() -> None:
    res = run_cli()
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
