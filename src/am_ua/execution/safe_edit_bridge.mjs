#!/usr/bin/env node
/**
 * MSEA SafeEditPlan Transactional Bridge (P4.3)
 * Drives `F:\MSEA_WORKTREES\mcp-runtime-v2\src\msea\runtime\safe_edit_plan.mjs`
 * (`applySafeEditPlan`, `rollbackSafeEditReceipt`, `recoverSafeEditJournal`)
 * without modifying a single byte in the upstream worktree.
 */

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const SAFE_EDIT_ROOT =
  process.env.MSEA_SAFE_EDIT_ROOT || "F:\\MSEA_WORKTREES\\mcp-runtime-v2";

async function loadSafeEdit() {
  const modUrl = pathToFileURL(
    path.join(SAFE_EDIT_ROOT, "src", "msea", "runtime", "safe_edit_plan.mjs")
  ).href;
  return await import(modUrl);
}

async function main() {
  const raw = fs.readFileSync(0, "utf8");
  const req = JSON.parse(raw || "{}");
  const { action, payload = {} } = req;
  const {
    applySafeEditPlan,
    rollbackSafeEditReceipt,
    recoverSafeEditJournal,
    SAFE_EDIT_PROTOCOL
  } = await loadSafeEdit();

  let result = null;
  if (action === "apply") {
    const plan = {
      protocol: SAFE_EDIT_PROTOCOL,
      ...payload.plan
    };
    result = await applySafeEditPlan(plan, payload.options || {});
  } else if (action === "rollback") {
    result = await rollbackSafeEditReceipt(
      String(payload.receiptPath),
      payload.options || {}
    );
  } else if (action === "recover") {
    result = await recoverSafeEditJournal(
      String(payload.journalPath),
      payload.options || {}
    );
  } else {
    throw new Error(`Unsupported safe_edit_bridge action: ${action}`);
  }

  process.stdout.write(JSON.stringify({ ok: true, action, result }) + "\n");
}

main().catch(err => {
  process.stdout.write(
    JSON.stringify({
      ok: false,
      code: err?.code || "safe_edit_bridge_error",
      error: err?.message || String(err),
      journalPath: err?.journalPath || null,
      recovery: err?.recovery || null
    }) + "\n"
  );
  process.exit(1);
});
