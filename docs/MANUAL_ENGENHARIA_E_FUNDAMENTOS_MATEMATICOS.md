# Manual de Engenharia Sênior e Fundamentos Matemáticos (`OmniExecutor v4.1`)

Este documento detalha os modelos matemáticos, invariantes de sistemas distribuídos e padrões de integração do **OmniExecutor (`AetherMind Universal Agent`)**. Cada seção apresenta a formulação exata implementada no código-fonte e explica como você pode transportar o mesmo modelo para outros tipos de projetos (APIs de alta carga, sistemas financeiros, compiladores, pipelines de dados, jogos ou robótica).

---

## 1. Resiliência de Estado e Execução Durável (`DurableExecutionEngine`)

### O Problema Clássico
Em agentes convencionais, se uma chamada de rede oscilar ou um comando externo der *timeout* no meio de uma missão de 15 passos, todo o progresso é perdido ou — pior — uma ação mutável (como cobrar um cartão, enviar uma mensagem ou aplicar um patch) é executada duas vezes.

### A Formulação no OmniExecutor (`src/am_ua/execution/durable_engine.py`)
Cada ferramenta registrada no sistema é classificada formalmente em uma de três classes algébricas de efeito (`EffectClass`):

1. **`PURE_READ`:** $f(s) = s$ (idempotente e livre de efeitos colaterais; pode ser repetida livremente).
2. **`IDEMPOTENT_WRITE`:** $f(f(s)) = f(s)$ (repetir a chamada com os mesmos argumentos converge para o mesmo estado final).
3. **`COMPENSATABLE_MUTATION`:** $f(s) = s'$ exige gravação prévia de *intent* em log transacional (`SQLite WAL`) com cerca de época monotônica (*Fencing Token* $\tau_k > \tau_{k-1}$).

Se um trabalhador com época $\tau_{\text{antiga}}$ tentar gravar no banco após outro coordenador assumir a época $\tau_{\text{nova}} > \tau_{\text{antiga}}$, o `FencedEffectWriter` rejeita a escrita imediatamente com `StaleLeaseFenceError`.

### Como Aplicar em Outros Projetos
- **Microsserviços de Pagamento e Pedidos:** nunca execute chamadas HTTP externas de cobrança sem gravar antes uma chave de idempotência (`step_id`) associada a um `lease_epoch` monotônico no banco relacional.
- **Orquestradores de ETL / Engenharia de Dados:** classifique cada etapa do pipeline em `PURE_READ`, `IDEMPOTENT_WRITE` ou `COMPENSATABLE_MUTATION` para permitir retomada automática (*resume from checkpoint*) apenas das etapas pendentes.

---

## 2. Calibração Epistêmica e Controle de Autonomia (`CalibrationLedger`)

### Formulação Matemática (`src/am_ua/contracts/calibration.py`)
Para impedir que um sistema autônomo tome decisões arriscadas quando está errando previsões em determinado domínio $D$, calculamos o **Escore de Brier** sobre uma janela deslizante de $N$ execuções verificadas por oráculo executável (como `pytest` ou verificação física de arquivo):

$$\text{BS}(D) = \frac{1}{N} \sum_{i=1}^{N} (p_i - o_i)^2 \in [0, 1]$$

onde:
- $p_i \in [0, 1]$ é a probabilidade de sucesso declarada pelo agente antes da verificação;
- $o_i \in \{0, 1\}$ é o resultado binário real do oráculo de teste ($\text{exit\_code} = 0 \implies 1$, caso contrário $0$).

Um escore $\text{BS}(D) = 0.0$ indica calibração perfeita; $\text{BS}(D) > 0.25$ indica que o agente está chutando ou superestimando sua capacidade.

### Como Aplicar em Outros Projetos
- **Motores de Aprovação Automática (Crédito, Seguros, Moderação):** mantenha um `CalibrationLedger` por categoria de cliente. Se o $\text{BS}$ subir após uma mudança de regra ou *drift* de dados, reduza automaticamente o limiar de aprovação automática e direcione casos limítrofes para fila humana.

---

## 3. Grafo de Código com PageRank e Sincronização Incremental (`PolyglotRepoMap` & `HierarchicalKnowledgeIndex`)

### Formulação Matemática (`src/am_ua/perception/polyglot_repomap.py`)
Dado um repositório com arquivos $V = \{f_1, f_2, \dots, f_n\}$, extraímos símbolos exportados (classes, funções, tabelas SQL) e referências cruzadas para montar a matriz de adjacência ponderada $W$. A relevância estrutural de cada arquivo $u$ é obtida iterando a equação de ponto fixo do PageRank:

$$PR^{(k+1)}(u) = \frac{1 - d}{n} + d \sum_{v \in \text{In}(u)} \frac{w_{vu}}{\sum_{z \in \text{Out}(v)} w_{vz}} PR^{(k)}(v)$$

Para manter o grafo atualizado em milissegundos durante edições contínuas (`src/am_ua/perception/knowledge_index.py`), mantemos o mapa de resumos criptográficos $H(f) = \text{SHA256}(\text{bytes}(f))$. Na chamada de `sync_changes()`, o conjunto de arquivos reindexados $\Delta V$ é restrito a:

$$\Delta V = \{f \in V_{\text{atual}} \mid f \notin V_{\text{anterior}} \lor H_{\text{atual}}(f) \ne H_{\text{anterior}}(f)\}$$

### Como Aplicar em Outros Projetos
- **Sistemas de Build e Testes Seletivos:** rode apenas os testes que alcançam o subgrafo impactado por $\Delta V$, ponderando a prioridade de execução pelo $PR(u)$ dos módulos alterados.
- **Geradores de Documentação Viva:** utilize `export_mermaid_graph()` em hooks de CI para atualizar automaticamente o diagrama de arquitetura da equipe a cada merge na branch principal.

---

## 4. Governança de Recursos Físicos e Escalonamento de Equipes (`HomeostasisGovernor` & `SubAgentSessionBus`)

### Formulação Matemática (`src/am_ua/governance/homeostasis.py`)
Para proteger a máquina contra exaustão de memória RAM, exaustão de espaço temporário em disco e loops improdutivos de LLM, o governador combina três invariantes:

1. **Força de Repulsão de Fronteira (Casimir):**
   $$F_{\text{casimir}}(r) = \frac{\alpha}{\max(\epsilon,\; r - r_{\min})^4}$$
   Quando a RAM livre ou o espaço livre em disco $r$ se aproxima de $r_{\min}$, o custo efetivo de abrir novos processos cresce com a quarta potência da distância até o limite, bloqueando novas alocações antes do travamento do sistema operacional.
2. **Escalonamento Adaptativo de Trabalhadores Paralelos (`compute_adaptive_worker_limit`):**
   $$W_{\max} = \min\left(8,\; \max\left(2,\; 2 + \left\lfloor \frac{\text{RAM}_{\text{livre\_MB}} - 2560}{1536} \right\rfloor\right)\right)$$
3. **Gatilho de Topologia de Equipe (`assess_team_topology`):**
   O escore de severidade $S \in [0, 10]$ soma indicadores de cardinalidade de domínios $D$, volume de arquivos $F$, criticidade operacional $C$ e diretiva explícita $T$:
   $$S = \min\left(10,\; \mathbb{I}_{|D|\ge 3}\cdot 3 + \mathbb{I}_{|D|=2}\cdot 2 + \mathbb{I}_{F>10}\cdot 2 + \mathbb{I}_{3 \le F \le 10}\cdot 1 + 3\cdot\mathbb{I}_C + 3\cdot\mathbb{I}_T\right)$$
   - $S \in [0, 2] \implies$ **Modo Solo** (1 especialista)
   - $S \in [3, 5] \implies$ **Dev Squad** (4 agentes em 3 ondas: Arquiteto → Engenheiro → Supervisor + TDD)
   - $S \in [6, 10] \implies$ **Executive Enterprise Fleet** (9 agentes em 4 ondas: CEO + Arquiteto → 3 Engenheiros/SRE → Supervisor + Auditor SAST → TDD + Auditor Estrito)

---

## 5. Evolução Constitucional com UCB1 e Dominância de Pareto (`ConstitutionalEvolver`)

### Formulação Matemática (`src/am_ua/evolution/constitutional_evolver.py` & `governance/alpha_c13.py`)
Ao explorar melhorias de código ou heurísticas automaticamente:

1. **Seleção de Linhagem via UCB1:**
   $$\text{Score}_{\text{UCB1}}(i) = \hat{\mu}_i + c \sqrt{\frac{\ln N}{n_i}}$$
2. **Filtro Anti-Goodhart e Dominância de Pareto:**
   Nenhuma mutação pode melhorar uma métrica secundária (como velocidade) às custas de degradar a segurança ou adulterar os testes visíveis. A promoção exige:
   $$\text{Integrity}(\text{tests\_visible}) = 1 \quad \land \quad \text{PassRate}(A) \ge \text{PassRate}(B) \quad \land \quad \text{Cost}(A) \le \text{Cost}(B)$$

---

## 6. Verificação Neuro-Simbólica Causal e Z3 (`URENeuroSymbolicBridge`)

### Formulação Matemática (`src/am_ua/cognition/ure_bridge.py`)
Para decisões em que a correlação estatística do LLM não basta, o módulo neuro-simbólico valida:
1. **Gramática Livre de Contexto (CFG Sieve):** garante que comandos e payloads sigam produções formais livres de injeção.
2. **Intervenção Causal de Pearl ($\text{do}$-calculus):** distingue correlação observacional $P(Y \mid X)$ de efeito causal real $P(Y \mid \text{do}(X = x))$ ajustando pelos confundidores $Z$ (*Backdoor Adjustment*):
   $$P(Y \mid \text{do}(X = x)) = \sum_{z} P(Y \mid X = x, Z = z)\, P(Z = z)$$
3. **Verificação de Satisfatibilidade (Z3 / SMT Unsat-Core):** verifica se um conjunto de pré-condições e pós-condições de segurança admite contraexemplo lógico antes da execução física.
