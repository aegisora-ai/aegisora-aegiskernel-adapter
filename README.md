# 🛡️ Aegisora + AegisKernel Adapter

> **Full-Stack AI Agent Defense:** Connecting Aegisora's action-level governance with AegisKernel's deterministic POSIX syscall execution boundary.

---

## 🎯 Architecture Overview

Autonomous AI coding agents (CrewAI, LangGraph, AutoGen, Claude Code) interact with filesystems, databases, and bash terminals. Ensuring complete safety requires a two-phase defense loop:

```
[Agent Action / Tool Call Request]
                 │
                 ▼
    ┌──────────────────────────┐
    │     AEGISORA LAYER       │  ◄── Evaluates Intent, Policy & Safety Rules
    │  (Action-Level Decision) │      Output: ALLOW | BLOCK | ESCALATE
    └────────────┬─────────────┘
                 │
        ALLOW    │    BLOCK / ESCALATE
                 │    ┌───────────────────────────────┐
                 │    │ ❌ Denied before Execution    │
                 │    │ ⚠️ Held for Human Review      │
                 │    └───────────────────────────────┘
                 ▼
    ┌──────────────────────────┐
    │    AEGISKERNEL LAYER     │  ◄── Hardware-speed POSIX Interception (<0.016ms)
    │  (Host Syscall Boundary) │      Intercepts execve, subprocess & file writes
    └────────────┬─────────────┘
                 │
        PASS     │    BREAKOUT / TAMPER DETECTED
                 │    ┌───────────────────────────────┐
                 │    │ 🛡️ Hard Kill (EPERM / SIGKILL) │
                 │    └───────────────────────────────┘
                 ▼
    ┌──────────────────────────┐
    │  FORENSIC AUDIT EVIDENCE │  ◄── SHA-256 Hash Piped back to Aegisora Evidence Log
    └──────────────────────────┘
```

---

## 🚀 Key Defense Properties

1. **Dual-Layer Assurance:** Aegisora governs the high-level tool intent; AegisKernel prevents OS breakouts and reverse shells at the system call layer.
2. **Deterministic Latency:** Zero LLM evaluation overhead at execution time (<0.016ms POSIX kill).
3. **Cryptographic Traceability:** Every execution event generates an SHA-256 forensic audit hash.

---

## 💻 Quick Start

```python
from integrations.aegisora.adapter import AegisoraAegisKernelAdapter

adapter = AegisoraAegisKernelAdapter()

# Governed tool execution
verdict = adapter.execute_governed_action(
    action_name="terminal_bash",
    payload="ls -la ./workspace",
    target_fn=run_bash_command
)

print(f"Status: {verdict.status}")
print(f"Audit Hash: {verdict.forensic_hash}")
```

---

## 🧪 Benchmark Verification

Run the end-to-end integration benchmark:

```bash
python integrations/aegisora/test_adapter.py
```
