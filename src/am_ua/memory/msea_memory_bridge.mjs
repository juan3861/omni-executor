#!/usr/bin/env node
/**
 * MSEA Frankenstein Memory v5 Bridge (P3.3)
 * Connects Python `MSEAFrankensteinClient` to the proven ESM organ in
 * `F:\Modular Self-Evolving Agent (MSEA)\src\msea\memory\memory_organ.mjs`
 * WITHOUT modifying a single byte in the upstream MSEA directory.
 */

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const MSEA_ROOT = process.env.MSEA_ROOT || "F:\\Modular Self-Evolving Agent (MSEA)";

async function loadMseaModules() {
  const organUrl = pathToFileURL(path.join(MSEA_ROOT, "src", "msea", "memory", "memory_organ.mjs")).href;
  const answererUrl = pathToFileURL(path.join(MSEA_ROOT, "src", "msea", "memory", "evidence_answerer.mjs")).href;
  const { MseaMemoryOrgan } = await import(organUrl);
  const { answerFromEvidence, extractAtomicFactValue } = await import(answererUrl);
  return { MseaMemoryOrgan, answerFromEvidence, extractAtomicFactValue };
}

async function main() {
  const rawInput = fs.readFileSync(0, "utf8");
  const req = JSON.parse(rawInput || "{}");
  const { action, storePath, payload = {} } = req;
  if (!storePath) {
    throw new Error("storePath is required for isolated MSEA Frankenstein persistence");
  }
  fs.mkdirSync(path.dirname(path.resolve(storePath)), { recursive: true });

  const { MseaMemoryOrgan, answerFromEvidence, extractAtomicFactValue } = await loadMseaModules();
  const organ = new MseaMemoryOrgan({
    filePath: path.resolve(storePath),
    formation: { flushSize: 1, similarityThreshold: 0.96 },
    semantic: { enabled: false }
  });

  let result = null;
  if (action === "ingest") {
    const items = Array.isArray(payload.items) ? payload.items : [payload];
    const written = [];
    for (const item of items) {
      const batch = organ.ingest(item, { flush: true });
      written.push(...batch);
    }
    result = { written };
  } else if (action === "retrieve") {
    const hits = organ.retrieve(String(payload.query || ""), payload.options || {});
    const evidence = answerFromEvidence(hits, payload.contract || {});
    result = { hits, evidence };
  } else if (action === "learn_outcome") {
    const outcome = organ.learnOutcome(
      payload.memoryIds || [],
      Boolean(payload.pass),
      payload.options || {}
    );
    const atoms = organ.store.all({ includeInactive: true });
    result = { outcome, atoms };
  } else if (action === "govern") {
    const report = organ.govern({
      confidenceThreshold: Number(payload.confidenceThreshold ?? 0.25),
      now: Number(payload.now ?? Date.now())
    });
    const atoms = organ.store.all({ includeInactive: true });
    result = { report, atoms };
  } else if (action === "inspect") {
    const atoms = organ.store.all({ includeInactive: Boolean(payload.includeInactive ?? true) });
    const extracted = atoms.map(a => ({ id: a.id, value: extractAtomicFactValue(a) }));
    result = { atoms, extracted };
  } else if (action === "snapshot") {
    result = organ.snapshot(String(payload.name || "default"), payload.meta || {});
  } else {
    throw new Error(`Unsupported MSEA bridge action: ${action}`);
  }

  process.stdout.write(JSON.stringify({ ok: true, action, result }) + "\n");
}

main().catch(err => {
  process.stdout.write(
    JSON.stringify({
      ok: false,
      error: err?.message || String(err),
      stack: err?.stack || null
    }) + "\n"
  );
  process.exit(1);
});
