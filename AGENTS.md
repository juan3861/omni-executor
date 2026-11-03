# AGENTS.md — Constituição Operacional & Sistema Anti-Perda (`F:\AetherMind_Universal_Agent`)

## 1. PRIMEIRO COMANDO OBRIGATÓRIO AO ENTRAR NESTE REPOSITÓRIO
Antes de ler dezenas de arquivos, supor onde o projeto parou ou editar código, **execute imediatamente**:
```powershell
F:\AetherMind_Universal_Agent\aether-compass.cmd resume-brief
```
Ou leia:
- `START_HERE.md` (mapa rápido das camadas)
- `AETHERMIND_NARRATIVE_STATE.md` (estado vivo gerado automaticamente pela bússola)
- `PAINEL_HUMANO.md` (tabela das 7 fases e 27 subfases `P0.1` → `P6.4` com hashes SHA-256)
- `project/LIVE_STATE.json` (estado JSON estruturado)

## 2. COMO FUNCIONA A GARANTIA ANTI-PERDA / ANTI-DRIFT (`ProjectCompass`)
1. Todas as **7 fases (`P0`–`P6`) e 27 subfases (`P0.1`–`P6.4`)** estão declaradas em `project/MASTER_PHASES.json` como um DAG determinístico.
2. **Proibido marcar subfase como concluída no grito:** somente `aether-compass.cmd verify <SUBFASE_ID>` pode promover uma subfase após provar:
   - Existência física e `size > 0` de todos os `required_files`,
   - Ausência total de marcadores de stub/mock,
   - Presença real de todos os `required_symbols`,
   - Execução real do `test_command` com `Exit Code 0`,
   - Integridade intacta dos arquivos selados em `constitution/SEAL_SHA256_MANIFEST.json`.
3. Se um agente anterior caiu no meio de uma edição, `aether-compass.cmd status` acusa **`drift_alerts`** comparando o SHA-256 em disco com o recibo SQLite WAL (`data/compass_ledger.db`).

## 3. LEIS INVIOLÁVEIS DO ECOSSISTEMA DO MESTRE RUAN
1. **Intocáveis Externos:** JAMAIS modifique, limpe ou grave arquivos temporários em `F:\rotor-llm`, `C:\Users\juanp\WorkBuddy AI\2026-09-22-20-59-03\rotor-seed`, `D:\AetherRE_Megazord`, `F:\Modular Self-Evolving Agent (MSEA)`, `F:\MSEA_WORKTREES\mcp-runtime-v2` ou `E:\Tools\maps\aetherscan`. Tudo se conecta via MCP/HTTP/CLI/imports read-only ou cópia com provenance em `vendor/`.
2. **Hardware Lock (AMD RX 580 + Discos):** Proibido `-ngl 99` Vulkan. Sempre manter `TMP=F:\AetherMind_Temp`, `TEMP=F:\AetherMind_Temp` e `CARGO_TARGET_DIR=F:\AetherMind_Cargo_Target` (`C:` tem ~2 GB e `E:\rotor_tmp` tem ~80 MB).
3. **Zero Push Remoto:** Proibido `git push` ou `gh repo create` até homologação completa e ordem explícita do Mestre Ruan.
4. **Zero RPA Cego:** Automação web/GUI roda obrigatoriamente em janela isolada, verifica DOM/UIA/OCR antes e depois, e fecha a janela isolada no `release()`.
5. **Juiz != Ator:** A homologação final exige `Exit Code 0` no `F:\AetherMind_Apotheosis_Final\aethermind_apotheosis\AetherMind_Strict_Auditor.py`.
