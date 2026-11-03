---
description: Regras Soberanas do Workspace AetherMind Universal Agent v3.1 (Super-União)
---

# AetherMind Universal Agent v3.1 — Regras do Workspace

1. **Bússola Anti-Perda Obrigatória no Boot:** Sempre execute `F:\AetherMind_Universal_Agent\aether-compass.cmd resume-brief` ao iniciar qualquer sessão para verificar as 27 subfases (`P0.1`..`P6.4`) e confirmar `Drift alerts: 0`.
2. **Único Dono de Estado:** Apenas `DurableExecutionEngine` (`src/am_ua/execution/durable_engine.py`) pode mutar estado transacional de missão (`SingleStateOwnerGuard`).
3. **Selo Constitucional Inviolável:** Nunca altere `constitution/IMMUTABLE_CONSTITUTION.json`, `eval/chaos_qualification_suite.py` ou `src/am_ua/governance/seal_guard.py` sem autorização explícita do Mestre Ruan e re-selagem formal.
4. **Travas Físicas de Hardware:**
   - Sempre force `TMP=F:\AetherMind_Temp` e `TEMP=F:\AetherMind_Temp`.
   - Jamais utilize `-ngl 99` na GPU RX 580.
   - Repositórios externos congelados (`F:\rotor-llm`, `rotor-seed`, `D:\AetherRE_Megazord`, `MSEA`, `E:\Tools\maps\aetherscan`) são estritamente somente-leitura.
5. **CLI Soberano:** Dispare diagnósticos e missões via `F:\AetherMind_Universal_Agent\aether-ua.cmd`.
