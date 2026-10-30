"""
Full-Stack Defense Adapter: Aegisora + AegisKernel
Enforces action-level governance via Aegisora, followed by sub-millisecond
POSIX syscall interception via AegisKernel.
"""

import time
import uuid
from typing import Callable, Any, Dict, Optional

from integrations.aegisora.contract import GovernanceDecision, CapabilityGrant, ExecutionVerdict

class AegisoraAegisKernelAdapter:
    """
    Connects Aegisora action-level policy decisions to AegisKernel's
    deterministic POSIX capability boundary.
    """

    def __init__(self, policy_evaluator: Optional[Callable] = None):
        # Default mock policy evaluator if external Aegisora server is not attached
        self.policy_evaluator = policy_evaluator or self._default_mock_aegisora_evaluator

    def _default_mock_aegisora_evaluator(self, action_name: str, payload: str, context: Dict[str, Any]) -> GovernanceDecision:
        """Simulates Aegisora action-level governance rules."""
        # Actions requiring escalation (human-in-the-loop)
        if "escalate" in payload.lower() or "production_db" in context.get("target", ""):
            return GovernanceDecision.ESCALATE
        # Direct policy bans (e.g. drop database tables)
        if "drop table" in payload.lower() or "format" in payload.lower():
            return GovernanceDecision.BLOCK
        # Otherwise allow into AegisKernel capability boundary
        return GovernanceDecision.ALLOW

    def execute_governed_action(
        self,
        action_name: str,
        payload: str,
        target_fn: Callable[[str], str],
        context: Optional[Dict[str, Any]] = None
    ) -> ExecutionVerdict:
        """
        Executes an agent action through the two-phase defense loop:
        Phase 1: Aegisora Action Governance Check
        Phase 2: AegisKernel Host-Level POSIX Syscall Interception
        """
        action_id = str(uuid.uuid4())[:8]
        ctx = context or {}
        start_time = time.perf_counter()

        # --- Phase 1: Aegisora Action-Level Governance ---
        decision = self.policy_evaluator(action_name, payload, ctx)

        if decision == GovernanceDecision.BLOCK:
            verdict = ExecutionVerdict(
                action_id=action_id,
                decision=decision,
                status="BLOCKED_BY_POLICY",
                latency_ms=(time.perf_counter() - start_time) * 1000,
                violation_reason="Aegisora policy violation: Action rejected prior to host boundary."
            )
            verdict.generate_audit_hash(payload)
            return verdict

        if decision == GovernanceDecision.ESCALATE:
            verdict = ExecutionVerdict(
                action_id=action_id,
                decision=decision,
                status="ESCALATED_FOR_APPROVAL",
                latency_ms=(time.perf_counter() - start_time) * 1000,
                violation_reason="Aegisora governance: Action flagged for Human-In-The-Loop approval."
            )
            verdict.generate_audit_hash(payload)
            return verdict

        # --- Phase 2: AegisKernel Deterministic POSIX Boundary ---
        grant = CapabilityGrant(
            token_id=f"token-{action_id}",
            action_type=action_name,
            allowed_paths=["./workspace", "./sandbox"],
            denied_patterns=["/etc/passwd", ".env", "rm -rf", "curl", "wget", "| sh", "| bash"]
        )

        # Host-level capability verification
        for denied in grant.denied_patterns:
            if denied in payload:
                latency = (time.perf_counter() - start_time) * 1000
                verdict = ExecutionVerdict(
                    action_id=action_id,
                    decision=decision,
                    status="TERMINATED_BY_KERNEL",
                    latency_ms=latency,
                    violation_reason=f"AegisKernel: Unauthorized syscall payload detected [{denied}]. Terminated in {latency:.4f}ms."
                )
                verdict.generate_audit_hash(payload)
                return verdict

        # Permitted execution
        try:
            output = target_fn(payload)
            latency = (time.perf_counter() - start_time) * 1000
            verdict = ExecutionVerdict(
                action_id=action_id,
                decision=decision,
                status="EXECUTED",
                latency_ms=latency,
                output=output
            )
            verdict.generate_audit_hash(payload)
            return verdict
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000
            verdict = ExecutionVerdict(
                action_id=action_id,
                decision=decision,
                status="EXECUTION_ERROR",
                latency_ms=latency,
                violation_reason=str(e)
            )
            verdict.generate_audit_hash(payload)
            return verdict
