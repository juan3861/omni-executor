# Cold-Team Operations, Verification & Rollback Runbook

## 1. Instant Continuation & Drift Audit
```powershell
F:\AetherMind_Universal_Agent\aether-compass.cmd status
F:\AetherMind_Universal_Agent\aether-compass.cmd verify-all
```

## 2. Universal Agent CLI
```powershell
F:\AetherMind_Universal_Agent\aether-ua.cmd doctor
F:\AetherMind_Universal_Agent\aether-ua.cmd radar F:\AetherMind_Universal_Agent\src
F:\AetherMind_Universal_Agent\aether-ua.cmd repomap F:\AetherMind_Universal_Agent\src
```

## 3. Transactional Rollback Procedure
- Every code edit applied via `SafeEditTransactionalJournal` writes `.original` backups and `receipt.json` under `.agent_comm/safe_edits/<planId>/`.
- Automatic rollback fires immediately if `StaticVerificationGate` detects SAST vulnerabilities, leaked secrets, or syntax errors.
- Manual rollback: invoke `SafeEditTransactionalJournal(root).rollback(receipt_path)`.
