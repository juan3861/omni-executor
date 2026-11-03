# START_HERE — Entrada Rápida para Agentes e Humanos (`F:\AetherMind_Universal_Agent`)

1. **Descubra onde parou em 1 segundo:**
   `F:\AetherMind_Universal_Agent\aether-compass.cmd resume-brief`
2. **Consulte o painel visual das 27 subfases:** [PAINEL_HUMANO.md](PAINEL_HUMANO.md) e [AETHERMIND_NARRATIVE_STATE.md](AETHERMIND_NARRATIVE_STATE.md).
3. **Execute o Agente Universal / Diagnóstico Completo:**
   `F:\AetherMind_Universal_Agent\aether-ua.cmd doctor`

## Mapa Modular (`src/am_ua/`)
| Órgão | Diretório | Responsabilidade |
|---|---|---|
| **Governança & Homeostase (`AM-08`)** | `src/am_ua/governance/` | `ConstitutionSealGuard` (SHA-256 real) + `HomeostasisGovernor` (Casimir + Stop-Loss `R09`) |
| **Contratos & Calibração (`M0`/`R01`–`R06`)** | `src/am_ua/contracts/` | `CognitiveEnvelope v1`, 6 Contratos Factory, `ProblemFramingGate`, `HypothesisRecord`, `CalibrationLedger` |
| **Segurança DPAPI** | `src/am_ua/security/` | `WindowsDPAPIProvider` (`CryptProtectData`) + `AuthenticatedEnvelopeManager` + Anti-Replay |
| **Execução Durável & Músculo (`M3`/`R08`/`S1`-`S2`)** | `src/am_ua/execution/` | `DurableExecutionEngine` (`OUTCOME_UNKNOWN` + `reconcile_step`), `FairDispatchScheduler`, `FencedEffectWriter`, `CodexSandboxMuscle`, `SafeEditTransactionalJournal` (`StaticVerificationGate` SAST), `WorktreeIsolationManager`, `E2B` |
| **Runtime Win32 & Maestro OMH** | `src/am_ua/runtime/` + `vendor/` | `hermes-win32-native` (PTC TCP+HMAC, JobObjects, `msvcrt`), `oh-my-hermes v4.0.4` (`/dag-ulw`), `PersistentPwsh`, `SpillToDisk`, `ExperimentalArbitrator` (`R10`) |
| **Memória Tripla (`AM-02`/`R13`)** | `src/am_ua/memory/` | `Letta` Core Blocks + `F:\Mnemos` Bi-Temporal + `MSEA Frankenstein v5` Q-Utility/Provenance |
| **Olhos Multi-Escala (`AM-01`/`M1`–`M2`)** | `src/am_ua/perception/` | `AetherScan v1.3.0` (61 ms + UCIP), `aider RepoMap` PageRank, `ast-grep`, `OMNI_TOPOLOGY_V2`, MCP Federation (`codebase-memory-mcp`, `AetherRE`) |
| **Roteador Cognitivo Universal** | `src/am_ua/routing/` | `OmniRoute v3.8.51` (`/v1/responses` + RTK) + `Mesh Translator` + `rotor-llm` (`:3700`) read-only adapter |
| **GUI/Browser Fechado, Docs & OSINT (`AM-06`/`S3`)** | `src/am_ua/gui/` | `VerifiedBrowserAdapter` (contrato `oh-my-hermes` + Stagehand + PAF + RPA Bridge janela isolada) + `DocumentMultimodalOrgan` (`.docx`/`.xlsx`/`.pdf` Taint `R16`) + `OlhoDeDeusOSINT` |
| **Neuro-Simbólico & Evolução (`AM-04`/`AM-07`)** | `src/am_ua/cognition/` & `evolution/` | `URE Alpha-C10` (`CFG Sieve`, `Pearl`, `Z3`, `TimeTravel`) + `ASI-Evolve` (`UCB1`/`MAP-Elites`) + `AutoHarness` |
| **Kernel, OTel, Triggers & Handoff (`R18`/`S4`-`S5`)** | `src/am_ua/agent_kernel.py` & `lifecycle/` | `AetherMindUniversalAgent` (`SingleStateOwner`), `TelemetrySpanLedger` (OTel JSONL), `AutonomousTriggerScheduler`, `HandoffPackExporter` + `chaos_qualification_suite.py` (7 cenários Harbor) |
