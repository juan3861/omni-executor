# Contributing to OmniExecutor Agent

Thank you for contributing to OmniExecutor Agent! This repository enforces strong runtime invariants (durable SQLite-WAL execution, SHA-256 constitutional sealing, static analysis, and automated regression tests). Please follow the checklist below before submitting a pull request.

---

## Development Setup

```powershell
git clone https://github.com/juan3861/omni-executor.git
cd omni-executor
pip install -e .
```

Optional organ dependencies (install only if modifying browser or desktop modules):

```powershell
pip install playwright pytesseract pillow numpy uiautomation
playwright install chromium
```

---

## Verification Gate (Required Before Any PR)

Run all three verification commands from the repository root and confirm clean pass results:

```powershell
# 1. Automated test suite (74 unit & integration tests)
pytest tests -q

# 2. Multi-organ & SHA-256 constitutional readiness audit
.\omni-executor.cmd doctor

# 3. Static security & secret scanner (must return Grade A, 0 findings)
.\omni-executor.cmd shield .
```

When scanning a workspace or target package with source SAST rules enabled:

```python
from am_ua.security.agent_shield import AgentShieldAuditor

report = AgentShieldAuditor().scan_directory("path/to/workspace", include_source_sast=True)
print(report.grade, len(report.findings), report.passed)
```

*(Note: Running `include_source_sast=True` across the repository root flags intentional regex definitions inside `security/agent_shield.py` and adversarial test fixtures under `tests/` and `eval/`.)*

---

## Extending OmniExecutor Agent

### 1. Adding a Workspace Tool (`AgentLoop`)
1. Implement the handler method inside `WorkspaceTools` (`src/am_ua/execution/agent_loop.py`), keeping path resolution inside `self.resolve(...)` and guarding mutations through `self.seal_guard`.
2. Assign its exact side-effect classification in `AgentLoop.TOOL_EFFECTS` (`EffectClass.PURE_READ`, `EffectClass.IDEMPOTENT_WRITE`, or `EffectClass.COMPENSATABLE_MUTATION`).
3. Document the JSON schema cleanly in `SYSTEM_PROMPT`, `SPARC_SYSTEM_PROMPT`, and [`README.md`](README.md).
4. Add unit/integration coverage under `tests/`.

### 2. Adding a Specialist Persona
1. Create a Markdown contract in `constitution/personas/<role_id>.md` with YAML frontmatter (`name`, `description`, `vibe`, `emoji`, `role`).
2. Register any short CLI alias inside `PersonaManager.get_persona()` (`src/am_ua/cognition/personas.py`).

### 3. Adding or Wrapping a Dynamic Skill
Use `AdaptiveSkillForge.forge_skill()` or `AdaptiveSkillForge.wrap_cli_tool()` (`src/am_ua/execution/adaptive_skills.py`). Every generated skill must pass the AST security validator and include deterministic parameter validation.

---

## Protected Zones (Read This First)

- **`constitution/` and `eval/` are SHA-256 sealed.** Unauthorized edits to sealed governance manifests or evaluation suites cause `omni-executor.cmd doctor` (`seal_valid: false`) and the constitution guard tests to fail immediately. Do **not** alter benchmark tasks or constitutional boundaries inside regular feature PRs.
- **Zero leaked credentials.** Never place live tokens or unredacted environment secrets in code, tests, `.json` fixtures, or Markdown documentation. The pre-write hook (`PreWriteSecretGuard`) and `omni-executor.cmd shield .` enforce this strictly.

---

## Coding Standards

- Keep modules focused and respect the layered topology (`governance` -> `contracts` -> `cognition` / `perception` / `memory` / `execution` -> `agent_kernel`).
- Support real failure reporting rather than silent swallows or mock green stubs; when a capability requires external API keys or optional binaries (`playwright`, `pytesseract`), degrade cleanly with structured error metadata.
- Update [`README.md`](README.md) or [`docs/ENGINEERING_AND_MATH_MANUAL.md`](docs/ENGINEERING_AND_MATH_MANUAL.md) whenever adding CLI subcommands, environment variables, or algorithmic behavior.
