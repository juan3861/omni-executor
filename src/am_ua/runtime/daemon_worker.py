"""Always-On Durable Daemon Worker with Crash Lease Recovery & Record-and-Replay (v13.0).

Consumes tasks continuously from `DurableDaemonQueue`, recovers stale leases after
process crashes or machine reboots, executes tasks via an injected runner or `AgentLoop`
with Temporal/Restate-style `RecordReplayEngine` journal persistence, and applies
exponential backoff on transient failures.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.execution.record_replay import DeterministicRecordReplayEngine
from am_ua.runtime.daemon_queue import DurableDaemonQueue
from am_ua.runtime.scheduler_receipts import RecurringScheduleStore


class DurableDaemonWorker:
    """Crash-resilient background worker pool over `DurableDaemonQueue` + `DeterministicRecordReplayEngine`."""

    def __init__(
        self,
        queue: DurableDaemonQueue,
        *,
        worker_id: str = "omni-worker-1",
        executor_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        replay_db_path: Optional[Path | str] = None,
        schedule_store: Optional[RecurringScheduleStore] = None,
        stale_lease_s: float = 300.0,
        max_attempts: int = 3,
        base_backoff_s: float = 5.0,
        on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.queue = queue
        self.worker_id = worker_id
        self.executor_fn = executor_fn
        self.stale_lease_s = max(1.0, float(stale_lease_s))
        self.max_attempts = max(1, int(max_attempts))
        self.base_backoff_s = max(0.0, float(base_backoff_s))
        self.on_event = on_event
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        replay_p = Path(replay_db_path) if replay_db_path else (queue.db_path.parent / "daemon_replay.db")
        durable_p = queue.db_path.parent / "daemon_durable.db"
        self.durable_engine = DurableExecutionEngine(durable_p)
        self.replay_engine = DeterministicRecordReplayEngine(replay_p)
        self.schedule_store = schedule_store or RecurringScheduleStore(queue.db_path.parent / "schedules.db")
        self.processed_count = 0
        self.recovered_count = 0
        self.wake_catchups_count = 0

    def _emit(self, event: str, **payload: Any) -> None:
        if self.on_event:
            try:
                self.on_event({"event": event, "worker_id": self.worker_id, "ts": time.time(), **payload})
            except Exception:
                pass

    def _default_execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a queued task through `AgentLoop` (Turn-0 deterministic first, LLM fallback)."""
        from am_ua.execution.agent_loop import AgentLoop
        from am_ua.governance.seal_guard import ConstitutionSealGuard

        ws = Path(str(task.get("workspace") or ".")).resolve()
        obj = str(task.get("objective") or "").strip()
        tid = str(task.get("task_id") or "daemon-task")
        loop = AgentLoop(engine=self.durable_engine, seal_guard=ConstitutionSealGuard())
        res = loop.run(
            objective=obj,
            workspace=ws,
            mission_id=tid,
            max_turns=16,
            use_judge=False,
            auto_compile_playbook=True,
        )
        ok = res.status.startswith("VERIFIED") or res.status == "COMPLETED_UNVERIFIED"
        return {"ok": ok, "status": res.status, "summary": res.final_summary, "result": asdict(res)}

    def tick(self, *, recover_stale: bool = True, enqueue_due_schedules: bool = True) -> Dict[str, Any]:
        """Run one atomic schedule-catchup + lease-recovery + claim + record-replay execution cycle."""
        recovered = 0
        if recover_stale:
            recovered = self.queue.recover_stale_leases(stale_after_s=self.stale_lease_s)
            if recovered:
                self.recovered_count += recovered
                self._emit("leases_recovered", count=recovered)

        if enqueue_due_schedules and self.schedule_store is not None:
            for sched in self.schedule_store.pop_due_schedules():
                if sched.get("wake_catchup"):
                    self.wake_catchups_count += 1
                    self._emit("wake_after_sleep_catchup", schedule_id=sched["schedule_id"], missed_windows=sched["missed_windows"])
                self.queue.enqueue(
                    str(sched["objective"]),
                    str(sched["workspace"]),
                    priority=70,
                    source=f"schedule:{sched['schedule_id']}",
                )

        task = self.queue.claim_next(self.worker_id)
        if task is None:
            return {"ok": True, "claimed": False, "recovered": recovered, "task_id": None}

        tid = str(task["task_id"])
        attempts = int(task.get("attempts") or 1)
        self._emit("task_claimed", task_id=tid, attempts=attempts, objective=str(task.get("objective", ""))[:160])

        runner = self.executor_fn or self._default_execute

        try:
            rec_sess = self.replay_engine.start_recording(f"daemon-{tid}-a{attempts}", "daemon_task")
            res = rec_sess.activity(
                "execute_daemon_task",
                {"task_id": tid, "attempt": attempts},
                lambda: runner(task),
            )
            rec_sess.finish(res if isinstance(res, dict) else {"value": res})
            if isinstance(res, dict) and not res.get("ok", True):
                err = str(res.get("error") or res.get("status") or "task_failed")
                retry_delay = self.base_backoff_s * (2 ** max(0, attempts - 1)) if attempts < self.max_attempts else None
                self.queue.fail(tid, err, retry_delay_s=retry_delay)
                self._emit("task_failed", task_id=tid, attempts=attempts, retry_delay_s=retry_delay, error=err)
                return {
                    "ok": False,
                    "claimed": True,
                    "task_id": tid,
                    "status": "requeued" if retry_delay is not None else "failed",
                    "recovered": recovered,
                    "error": err,
                }
            self.queue.complete(tid, res if isinstance(res, dict) else {"value": res})
            self.processed_count += 1
            receipt = None
            if self.schedule_store is not None:
                try:
                    sched_id = str(task.get("source") or "").split(":", 1)[1] if str(task.get("source") or "").startswith("schedule:") else None
                    receipt = self.schedule_store.record_receipt(
                        mission_id=tid,
                        schedule_id=sched_id,
                        status=str(res.get("status") or "completed") if isinstance(res, dict) else "completed",
                        cost_usd=float(res.get("cost_usd", 0.0)) if isinstance(res, dict) else 0.0,
                    )
                except Exception:
                    receipt = None
            self._emit("task_completed", task_id=tid, attempts=attempts, receipt_id=(receipt or {}).get("receipt_id"))
            return {
                "ok": True,
                "claimed": True,
                "task_id": tid,
                "status": "completed",
                "recovered": recovered,
                "result": res,
                "receipt": receipt,
            }
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            retry_delay = self.base_backoff_s * (2 ** max(0, attempts - 1)) if attempts < self.max_attempts else None
            self.queue.fail(tid, err, retry_delay_s=retry_delay)
            self._emit("task_exception", task_id=tid, attempts=attempts, retry_delay_s=retry_delay, error=err)
            return {
                "ok": False,
                "claimed": True,
                "task_id": tid,
                "status": "requeued" if retry_delay is not None else "failed",
                "recovered": recovered,
                "error": err,
            }

    def run_until_empty(self, *, max_tasks: int = 50) -> Dict[str, Any]:
        """Drain currently due tasks synchronously (useful for CI, cron ticks, and tests)."""
        outcomes: List[Dict[str, Any]] = []
        for _ in range(max(1, int(max_tasks))):
            step = self.tick(recover_stale=(len(outcomes) == 0))
            if not step.get("claimed"):
                break
            outcomes.append(step)
        return {
            "ok": all(o.get("ok") for o in outcomes),
            "worker_id": self.worker_id,
            "processed": len(outcomes),
            "recovered_leases": self.recovered_count,
            "stats": self.queue.stats(),
            "outcomes": outcomes,
        }

    def start_background(self, *, poll_interval_s: float = 1.0) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()

        def _loop() -> None:
            while not self._stop_event.is_set():
                step = self.tick(recover_stale=True)
                if not step.get("claimed"):
                    self._stop_event.wait(timeout=max(0.1, poll_interval_s))

        self._thread = threading.Thread(target=_loop, name=f"daemon-{self.worker_id}", daemon=True)
        self._thread.start()

    def stop(self, *, timeout_s: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout_s)
            self._thread = None
