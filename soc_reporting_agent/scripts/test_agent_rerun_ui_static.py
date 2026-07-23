from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
app = (ROOT / "dashboard" / "app.js").read_text(encoding="utf-8")
backend = (ROOT / "backend" / "app.py").read_text(encoding="utf-8")

checks = []


def check(name, condition):
    checks.append((name, bool(condition)))


check("frontend stores per-agent rerun guards", "agentRunGuards" in app and "agentRunGuardSequence" in app)
check("rerun marks guard before awaiting backend", 'markAgentRunStarting(agentKey, ticketId, "rerun")' in app and 'render();\n  const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/agents/${encodeURIComponent(agentKey)}/rerun`' in app)
check("run marks guard before awaiting backend", 'markAgentRunStarting(agentKey, ticketId, "run")' in app and 'render();\n  const endpoint = ticketId' in app)
check("currentAgentRun prefers guarded state", "const guarded = guardedRunForAgent(agent);" in app and "if (guarded) return guarded;" in app)
check("summary payload masks old output while guarded", "shouldMaskAgentOutput(ticket, agent.key || agentKey)" in app and "rawOutput = !shouldMaskAgentOutput" in app)
check("summary downloads disable without fresh output", "disabledDownloadButton(\"Download JSON\"" in app and "if (!hasOutput)" in app)
check("reporting workspace masks old reports while rerunning", "reporting-rerun-placeholder" in app and "if (shouldMaskAgentOutput(ticket, \"reporting\"))" in app)
check("view output blocks guarded stale output", "The latest run is still in progress or failed. Active output is not available yet." in app)
check("polling uses currentAgentRun instead of first stale run", "const run = agent ? currentAgentRun(agent) : null;" in app and "const updated = currentAgentRun(agent);" in app)
check("failed run states are not treated as completed", '"execution_error", "timed_out", "timeout", "paused"' in app and "run.success === false" in app)
check("backend start response includes started_at", '"started_at": run_record["started_at"]' in backend)
check("backend existing-run response includes progress metadata", '"progress_percent": current.get("progress_percent")' in backend and '"progress_percent": existing_active.get("progress_percent")' in backend)

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
if failed:
    raise SystemExit(f"Failed checks: {failed}")
print(f"\nPassed {len(checks)} agent rerun UI checks.")
