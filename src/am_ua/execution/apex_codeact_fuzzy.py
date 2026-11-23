"""Apex CodeAct, Fuzzy Search/Replace & Senior Readiness Engines (`am_ua.execution.apex_codeact_fuzzy`)."""

from __future__ import annotations

from am_ua.execution.codeact_ast_runner import CodeActASTSandbox, DirtyWorktreeSnapshotGuard, _SnapshotEntry
from am_ua.execution.fuzzy_replace_engine import (
    AiderFuzzySearchReplaceEngine,
    _DEFAULT_TOPOLOGY_DAG,
    _SKIP_DIRS,
    _resolve_contained_path,
)
from am_ua.execution.pr_architecture_auditor import (
    SeniorArchitectReadinessAuditor,
    analyze_import_layers,
    strengthen_test_assertions,
)
from am_ua.execution.pr_review_scorecard import (
    check_api_backward_compat,
    compute_pr_review_scorecard,
    parse_exception_traceback,
)

__all__ = [
    "AiderFuzzySearchReplaceEngine",
    "CodeActASTSandbox",
    "DirtyWorktreeSnapshotGuard",
    "SeniorArchitectReadinessAuditor",
    "analyze_import_layers",
    "strengthen_test_assertions",
    "parse_exception_traceback",
    "check_api_backward_compat",
    "compute_pr_review_scorecard",
]
