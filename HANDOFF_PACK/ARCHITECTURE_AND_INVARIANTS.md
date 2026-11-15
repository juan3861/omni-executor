# AetherMind Universal Agent (Super-Union v3.1) — Architecture & Invariants

## 1. Sovereign Single-State-Owner Law
- **State Owner:** `DurableExecutionEngine` (`src/am_ua/execution/durable_engine.py`) backed by SQLite WAL.
- **Inter-Organ Contract:** `CognitiveEnvelope` (`src/am_ua/contracts/contracts.py`) protected by Windows DPAPI + anti-replay nonces.
- **Topology Contract (`OMNI_TOPOLOGY_V2`):** Acyclic 12-layer DAG (`ok=True`, checked_edges=`28`).

## 2. Constitutional & Hardware Invariants
- Sealed paths (`constitution/`, `eval/`, `src/am_ua/governance/seal_guard.py`) are byte-hashed with SHA-256.
- External untouchable repositories (`F:\rotor-llm`, `rotor-seed`, `D:\AetherRE_Megazord`, `MSEA`, `aetherscan`) are read-only.
- Hardware Lock: AMD Radeon RX 580 forbids `-ngl 99`; `TMP`/`TEMP` forced to `F:\AetherMind_Temp`.
- Epistemic Safety: `TrustLevel.UNTRUSTED_DATA` (R16) cannot authorize mutative tools; `TIMEOUT -> OUTCOME_UNKNOWN` (R08) requires `reconcile_step()`.
