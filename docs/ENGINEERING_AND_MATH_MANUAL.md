# Engineering and Mathematics Manual

This manual explains the models behind OmniExecutor Agent, states them exactly as implemented, and shows how each idea transfers to other kinds of systems. Source files are named next to each model so every claim can be checked against the code.

Notation: all formulas are rendered with GitHub's built-in math support.

---

## 1. Durable execution and effect fencing

**Source:** `src/am_ua/execution/durable_engine.py`

Every tool is classified by its side effects:

| Class | Meaning |
| :--- | :--- |
| `pure_read` | No state change. |
| `idempotent_write` | Repeating the call with the same arguments converges to the same state. |
| `compensatable_mutation` | Changes state but can be undone or reconciled. |
| `irreversible_external` | Cannot be undone (for example, a message already sent). |

**Retry semantics.** Each step is checkpointed by `(run_id, step_id)`. If a step already `COMPLETED`, the stored result is returned instead of executing it again. If a step times out mid-effect it is marked `OUTCOME_UNKNOWN`; any retry then raises `OutcomeUnknownError` until `reconcile_step()` determines what actually happened (a tool without a `reconcile_fn` requires operator resolution). This is what prevents a duplicated side effect after an ambiguous failure.

Idempotence of the middle class can be written as

```math
f(f(s)) = f(s)
```

**Lease fencing.** Each resource has a current lease epoch $\tau_{\mathrm{cur}}$. A worker holding epoch $\tau_w$ may mutate state only if

```math
\tau_w = \tau_{\mathrm{cur}}
```

Otherwise `assert_fence_valid` raises `StaleLeaseFenceError`. This blocks "zombie" workers that timed out and were superseded from writing late.

**Where to reuse it:** payment and order services (idempotency key plus epoch per step), ETL and workflow engines (classify each step to decide what can be resumed automatically), job queues with at-least-once delivery.

---

## 2. Calibration and autonomy tiers

**Source:** `src/am_ua/contracts/calibration.py`

For each engineering domain the ledger stores the predicted success probability $p_i \in [0,1]$ and the observed outcome $y_i \in \{0,1\}$ (the acceptance command's exit status). The mean Brier score and the overconfidence gap are

```math
\mathrm{BS} = \frac{1}{N}\sum_{i=1}^{N}(p_i - y_i)^2, \qquad
g = \max\!\left(0,\ \bar{p} - \bar{y}\right)
```

where $\bar{p}$ is the mean predicted confidence and $\bar{y}$ the empirical accuracy. With $N \ge 3$ samples, the tier is chosen as:

| Condition | Tier |
| :--- | :--- |
| $g > 0.20$ **or** $\mathrm{BS} > 0.25$ | `REQUIRE_DOUBLE_CHECK` |
| $\mathrm{BS} \le 0.10$ **and** $g \le 0.10$ | `FULL_AUTONOMY` |
| otherwise | `CAUTIOUS_VERIFY` |

With no samples the prior is $\mathrm{BS}=0.25$ and `CAUTIOUS_VERIFY`.

**Where to reuse it:** auto-approval engines (credit, fraud, moderation) that should fall back to human review when calibration degrades; CI gates that require extra review for a code generator whose predictions have drifted.

---

## 3. Code centrality: PageRank over a symbol graph

**Source:** `src/am_ua/perception/polyglot_repomap.py`

Symbol definitions and references are extracted (Python with `ast`; JS/TS, Rust and Go with lightweight parsers) into a weighted directed graph over $n$ files. Power iteration with damping $d = 0.85$ computes

```math
PR(u) = \frac{1-d}{n} + d \sum_{v \to u} PR(v)\,\frac{w_{vu}}{\sum_{z} w_{vz}}
```

The top-ranked files are rendered into a compact map that fits a token budget, instead of embedding the whole repository.

**Incremental index.** `HierarchicalKnowledgeIndex.sync_changes()` stores $H(f)=\mathrm{SHA256}(\mathrm{bytes}(f))$ per file and re-indexes only

```math
\Delta V = \{\, f \in V_{\mathrm{now}} \ :\ f \notin V_{\mathrm{before}} \ \lor\ H_{\mathrm{now}}(f) \neq H_{\mathrm{before}}(f) \,\}
```

plus removed files.

**Where to reuse it:** impact analysis in monorepos, selective test runs weighted by the centrality of changed modules, security review ordering, living architecture diagrams generated in CI.

---

## 4. Resource governance and worker scaling

**Source:** `src/am_ua/governance/homeostasis.py`, `src/am_ua/execution/subagent_bus.py`

**Hard floors (defaults).** The governor blocks new work when free space on the work drive drops below 1 GiB or free RAM below 384 MB, and aborts after a configurable number of stagnant turns (no verified progress).

**Storage-pressure signal.** With normalized free gap $d = \mathrm{free}/\mathrm{total}$ (clamped below at $10^{-6}$), the code evaluates a Casimir-style force

```math
F_c(d) = -\frac{\pi^2}{240\, d^{4}}
```

Its magnitude grows quickly as $d$ shrinks (the documented alarm region is $d < 0.20$), giving an early, smooth warning before an out-of-space failure. This is an engineering heuristic borrowed from the form of the physical law, not a physical model of the disk.

**Parallel worker ceiling.** A separate rule scales team parallelism from live free RAM (megabytes):

```math
W = \min\!\left(8,\ \max\!\left(2,\ 2 + \left\lfloor \frac{\mathrm{RAM}_{\mathrm{free}} - 2560}{1536} \right\rfloor\right)\right)
```

i.e. `2` workers up to 2.5 GB free, then one more worker per additional 1.5 GB, capped at `8`.

**Where to reuse it:** queue consumers (RabbitMQ, Kafka, Celery) that must not trigger OOM kills; local inference servers that should shrink batch size before paging hurts tail latency.

---

## 5. Team topology score

**Source:** `SubAgentSessionBus.assess_team_topology` in `src/am_ua/execution/subagent_bus.py`

Let $D$ be the set of matched domains (architecture, backend, frontend/browser, security, performance, testing), $F$ the workspace file count, and $C$, $T$ binary indicators for "critical/production wording" and "explicit team request". With $w$ equal to `2` for wide scope ($F>10$ or scope keywords), `1` for $3 \le F \le 10$, and `0` otherwise:

```math
S = \min\!\Big(10,\ 3\cdot\mathbf{1}[\lvert D\rvert \ge 3] + 2\cdot\mathbf{1}[\lvert D\rvert = 2] + w + 3\cdot C + 3\cdot T\Big)
```

```math
\text{mode}(S)=
\begin{cases}
\text{solo specialist (1 agent)} & S \le 2\\
\text{dev squad (4 agents, 3 waves)} & 3 \le S \le 5\\
\text{executive fleet (9 agents, 4 waves)} & S \ge 6
\end{cases}
```

Caps: spawn depth $\le 2$, at most `16` agents per mission, parallelism $\le W$ from section 4.

**Where to reuse it:** any dispatcher that should escalate from a single worker to a coordinated team only when scope, risk or explicit intent justify the coordination cost.

---

## 6. Evolutionary selection: UCB1 and gated promotion

**Source:** `src/am_ua/evolution/constitutional_evolver.py`

Parent selection balances exploitation and exploration with

```math
\mathrm{UCB}_i = \bar{x}_i + c\sqrt{\frac{\ln(N+1)}{n_i}}, \qquad c = 1.414
```

where $\bar{x}_i$ is the mean reward of candidate $i$, $n_i$ its visit count and $N$ the total visits. A behavioral archive keyed by `(complexity_bin, speed_bin)` keeps diverse elites (MAP-Elites style). A candidate becomes active only if it passes a **non-regression and baseline-superiority gate** and does not touch the sealed evaluation files.

**Where to reuse it:** A/B testing with multi-armed bandits, query-plan or compiler-heuristic tuning where a change must not regress any tracked metric.

---

## 7. Pipe-aware fail-closed command risk classification

**Source:** `classify_shell_command` and `evaluate_autonomy_gate` in `src/am_ua/execution/hook_engine.py`

Before a shell command runs, quoted heredoc and here-string literal bodies (`<< 'EOF'`, `@' ... '@`) are stripped as inert data while unquoted heredocs stay inspectable. The command is split quote-safely across pipes and chain operators (`|`, `&&`, `||`, `;`) into segments $\mathrm{seg}_1, \dots, \mathrm{seg}_m$, each assigned an ordered integer risk class $C(\mathrm{seg}_k) \in \{1:\mathrm{READ},\ 2:\mathrm{WRITE},\ 3:\mathrm{NETWORK},\ 4:\mathrm{INSTALL},\ 5:\mathrm{DESTRUCTIVE}\}$:

```math
C(\mathrm{cmd}) = \max_{1 \le k \le m} C(\mathrm{seg}_k)
```

where any segment not matching the deterministic read-only allowlist fails closed to $2\ (\mathrm{WRITE})$, and any segment sequence where $\mathrm{NETWORK}$ ($3$) pipes into a shell interpreter upgrades to $5\ (\mathrm{DESTRUCTIVE})$. Decisions (`ALLOW`, `PROMPT`, `BLOCK`) then evaluate deterministically against the active autonomy tier (`readonly`, `supervised`, `full`) and optional prefix allowlist.

**Where to reuse it:** CI/CD runners, developer assistants, and database migration CLI wrappers where chained commands must inherit the worst-case blast radius rather than trusting the first verb.

---

## 8. Two-stage calibrated tool & scope filtering

**Source:** `rank_tools_for_objective` and `ROLE_TOOL_SCOPES` in `src/am_ua/execution/agent_loop.py`

To avoid sending bloated tool schemas to weak or latency-bound models, tool selection runs in two deterministic stages:

1. **Candidate narrowing:** `ROLE_TOOL_SCOPES` restricts specialist roles (`strict_auditor`, `security_auditor`, `product_ceo`, `systems_architect`, `eng_supervisor`), and either `FamilyThenDecide` selects at most $2$ relevant tool families or `RetrieveThenDecide` pre-shortlists top-$K$ candidates ($K=20$) to form $\mathcal{C}(q)$.
2. **Calibrated filtering & thresholding:** Over $\mathcal{C}(q)$, BM25-style relevance logits $s(q, t)$ normalize via Softmax and drop tools below $p_{\min} = 0.05$:

```math
P(t \mid q) = \frac{\exp\!\big(s(q,t)\big)}{\sum_{j \in \mathcal{C}(q)} \exp\!\big(s(q,j)\big)}, \qquad \mathcal{T}(q) = \{\, t \in \mathcal{C}(q) : P(t \mid q) \ge p_{\min} \,\}
```

A separate binary estimate (`needs_tools_prob`) indicates whether the prompt needs workspace tools at all. In browser execution (`src/am_ua/gui/cdp_browser.py`), checkout/payment actions are guarded prior to DOM interaction (`block_on_payment=True`), halting before irreversible financial clicks.

**Where to reuse it:** large tool/plugin registries (50–500 MCP tools) where full-catalog schema injection blows context budgets or triggers hallucinated tool calls.

---

## 9. External reasoning components

`src/am_ua/cognition/ure_bridge.py` delegates formal checks to external components: an SMT solver (Z3) for consistency and minimal unsatisfiable cores, and a causal engine that audits claims of necessity and sufficiency of the form $do(X)$. `src/am_ua/memory/mnemos_connector.py` adapts an external long-term memory service. These integrations require those components to be installed and are not re-derived here; consult the respective projects for their mathematics.

---

## Verifying the claims yourself

```powershell
pytest tests -q                              # unit and integration tests
.\omni-executor.cmd doctor                   # readiness and seal verification
.\omni-executor.cmd shield .                 # static analysis
python eval\audit_top100_github.py           # parity audit (keyword and file-presence check)
```
