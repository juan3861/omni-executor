"""Cold-Team Handoff Pack Exporter (Astra R18) (P6.2).

Generates a self-contained, cryptographically fingerprinted `HANDOFF_PACK/` bundle so
any cold engineering team or autonomous agent can audit, reproduce, verify, or roll
back the system without prior chat history:
  - `ARCHITECTURE_AND_INVARIANTS.md`
  - `DECISION_AND_MEMORY_LEDGER.md`
  - `RUNBOOK_OPERATIONS_AND_ROLLBACK.md`
  - `KNOWN_LIMITATIONS_AND_RISKS.md`
  - `VERIFICATION_RECEIPT.json` (real content SHA-256 of core artifacts + calibration + seal).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from am_ua import PROJECT_ROOT
from am_ua.contracts.calibration import CalibrationLedger
from am_ua.governance.homeostasis import HomeostasisGovernor
from am_ua.governance.seal_guard import ConstitutionSealGuard, compute_content_sha256
from am_ua.memory import TriadMemoryProvider
from am_ua.perception import InterRepoTopologyGate


class HandoffPackExporter:
    """Exports R18 cold-team operational, architectural, and cryptographic handoff artifacts."""

    def __init__(self, project_root: Optional[Path | str] = None) -> None:
        self.root = Path(project_root or PROJECT_ROOT).resolve()
        self.seal_guard = ConstitutionSealGuard(self.root)
        self.homeostasis = HomeostasisGovernor()
        self.topology_gate = InterRepoTopologyGate()

    def export(
        self,
        output_dir: Optional[Path | str] = None,
        *,
        extra_evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        out_dir = Path(output_dir or (self.root / "HANDOFF_PACK")).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        homeo = self.homeostasis.sample()
        topo = self.topology_gate.audit_package_imports(self.root / "src" / "am_ua")
        seal_ok, seal_errs = self.seal_guard.verify_seal(require_manifest=False)
        cal = CalibrationLedger(self.root / "data" / "calibration_ledger.db")
        cal_stats = cal.domain_stats("software_engineering")

        # 1. ARCHITECTURE_AND_INVARIANTS.md
        arch_md = out_dir / "ARCHITECTURE_AND_INVARIANTS.md"
        arch_md.write_text(
            "\n".join(
                [
                    "# AetherMind Universal Agent (Super-Union v3.1) — Architecture & Invariants",
                    "",
                    "## 1. Sovereign Single-State-Owner Law",
                    "- **State Owner:** `DurableExecutionEngine` (`src/am_ua/execution/durable_engine.py`) backed by SQLite WAL.",
                    "- **Inter-Organ Contract:** `CognitiveEnvelope` (`src/am_ua/contracts/contracts.py`) protected by Windows DPAPI + anti-replay nonces.",
                    "- **Topology Contract (`OMNI_TOPOLOGY_V2`):** Acyclic 12-layer DAG (`ok="
                    + str(topo["ok"])
                    + f"`, checked_edges=`{topo['checked_edges']}`).",
                    "",
                    "## 2. Constitutional & Hardware Invariants",
                    "- Sealed paths (`constitution/`, `eval/`, `src/am_ua/governance/seal_guard.py`) are byte-hashed with SHA-256.",
                    "- External untouchable repositories (`F:\\rotor-llm`, `rotor-seed`, `D:\\AetherRE_Megazord`, `MSEA`, `aetherscan`) are read-only.",
                    "- Hardware Lock: AMD Radeon RX 580 forbids `-ngl 99`; `TMP`/`TEMP` forced to `F:\\AetherMind_Temp`.",
                    "- Epistemic Safety: `TrustLevel.UNTRUSTED_DATA` (R16) cannot authorize mutative tools; `TIMEOUT -> OUTCOME_UNKNOWN` (R08) requires `reconcile_step()`.",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        # 2. DECISION_AND_MEMORY_LEDGER.md
        mem_md = out_dir / "DECISION_AND_MEMORY_LEDGER.md"
        triad = TriadMemoryProvider(self.root / "data" / "triad_memory")
        mem_md.write_text(
            "\n".join(
                [
                    "# Decision, Calibration & Triad Memory Ledger",
                    "",
                    "## 1. Core Memory Blocks Snapshot",
                    "```xml",
                    triad.system_prompt_block(),
                    "```",
                    "",
                    "## 2. Domain Epistemic Calibration (`software_engineering`)",
                    f"- Samples: `{cal_stats.sample_count}`",
                    f"- Empirical Accuracy: `{cal_stats.empirical_accuracy}`",
                    f"- Mean Brier Score: `{cal_stats.mean_brier_score}`",
                    f"- Active Autonomy Tier: `{cal_stats.autonomy_tier}`",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        # 3. RUNBOOK_OPERATIONS_AND_ROLLBACK.md
        runbook_md = out_dir / "RUNBOOK_OPERATIONS_AND_ROLLBACK.md"
        runbook_md.write_text(
            "\n".join(
                [
                    "# Cold-Team Operations, Verification & Rollback Runbook",
                    "",
                    "## 1. Instant Continuation & Drift Audit",
                    "```powershell",
                    "F:\\AetherMind_Universal_Agent\\aether-compass.cmd status",
                    "F:\\AetherMind_Universal_Agent\\aether-compass.cmd verify-all",
                    "```",
                    "",
                    "## 2. Universal Agent CLI",
                    "```powershell",
                    "F:\\AetherMind_Universal_Agent\\aether-ua.cmd doctor",
                    "F:\\AetherMind_Universal_Agent\\aether-ua.cmd radar F:\\AetherMind_Universal_Agent\\src",
                    "F:\\AetherMind_Universal_Agent\\aether-ua.cmd repomap F:\\AetherMind_Universal_Agent\\src",
                    "```",
                    "",
                    "## 3. Transactional Rollback Procedure",
                    "- Every code edit applied via `SafeEditTransactionalJournal` writes `.original` backups and `receipt.json` under `.agent_comm/safe_edits/<planId>/`.",
                    "- Automatic rollback fires immediately if `StaticVerificationGate` detects SAST vulnerabilities, leaked secrets, or syntax errors.",
                    "- Manual rollback: invoke `SafeEditTransactionalJournal(root).rollback(receipt_path)`.",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        # 4. KNOWN_LIMITATIONS_AND_RISKS.md
        limits_md = out_dir / "KNOWN_LIMITATIONS_AND_RISKS.md"
        limits_md.write_text(
            "\n".join(
                [
                    "# Known Operational Boundaries & Honest Limitations (Radical Truth)",
                    "",
                    "1. **Cloud Sandboxes & SaaS APIs (`E2B`, `Exa`):** Require explicit operator API keys (`E2B_API_KEY`, `EXA_API_KEY`); when unset, the kernel honestly reports local fallback mode.",
                    "2. **Local GPU (`RX 580`):** Vulkan/llama.cpp `-ngl 99` is constitutionally blocked to prevent TDR driver crashes; local `rotor-llm` is consumed strictly via read-only HTTP (`:3700`).",
                    "3. **Physical Actuation (`ExecutionRealm.REQUIRES_PHYSICAL_ACTUATION`):** Digital verification never claims physical-world actuation without external sensor telemetry.",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        # 5. VERIFICATION_RECEIPT.json
        hashed_targets: List[str] = [
            "pyproject.toml",
            "project/MASTER_PHASES.json",
            "constitution/IMMUTABLE_CONSTITUTION.json",
            "src/am_ua/agent_kernel.py",
            "src/am_ua/execution/durable_engine.py",
            "src/am_ua/execution/codex_muscle.py",
            "src/am_ua/memory/triad_provider.py",
            "src/am_ua/gui/verified_browser_adapter.py",
            "src/am_ua/cognition/ure_bridge.py",
            "src/am_ua/evolution/constitutional_evolver.py",
        ]
        if (self.root / "eval" / "chaos_qualification_suite.py").is_file():
            hashed_targets.append("eval/chaos_qualification_suite.py")
        if (self.root / "constitution" / "SEAL_SHA256_MANIFEST.json").is_file():
            hashed_targets.append("constitution/SEAL_SHA256_MANIFEST.json")

        artifact_hashes = {
            rel: compute_content_sha256(self.root / rel)
            for rel in hashed_targets
            if (self.root / rel).is_file()
        }

        receipt_payload: Dict[str, Any] = {
            "schema_version": "aethermind_r18_handoff_receipt/v1",
            "exported_at_unix": time.time(),
            "project_root": str(self.root),
            "seal_valid": seal_ok,
            "seal_errors": seal_errs,
            "topology_v2": topo,
            "homeostasis_healthy": homeo.healthy,
            "safe_temp_dir": homeo.safe_temp_dir,
            "artifacts_sha256": artifact_hashes,
            "extra_evidence": extra_evidence or {},
        }
        receipt_path = out_dir / "VERIFICATION_RECEIPT.json"
        receipt_path.write_text(
            json.dumps(receipt_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        return {
            "output_dir": str(out_dir),
            "files": [
                str(arch_md),
                str(mem_md),
                str(runbook_md),
                str(limits_md),
                str(receipt_path),
            ],
            "receipt": receipt_payload,
        }
