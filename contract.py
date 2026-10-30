"""
Aegisora <-> AegisKernel Adapter Interface Contract
Defines the bidirectional data exchange between Aegisora's action governance
and AegisKernel's host-level deterministic capability boundary.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
import hashlib
import time

class GovernanceDecision(Enum):
    """Core decision states evaluated by Aegisora."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"

@dataclass
class CapabilityGrant:
    """
    Runtime capability tokens granted when Aegisora yields ALLOW.
    Passed directly into AegisKernel's low-level POSIX execution boundary.
    """
    token_id: str
    action_type: str                     # e.g. "shell_exec", "file_mutation", "api_call"
    allowed_paths: List[str] = field(default_factory=lambda: ["./workspace"])
    denied_patterns: List[str] = field(default_factory=lambda: [
        "/etc/passwd", ".env", "id_rsa", "rm -rf", "curl", "wget", "| sh", "| bash", "2>&1"
    ])
    max_memory_mb: int = 512
    timeout_ms: float = 50.0

@dataclass
class ExecutionVerdict:
    """
    Deterministic execution result and forensic audit payload
    piped back into Aegisora's evidence log.
    """
    action_id: str
    decision: GovernanceDecision
    status: str                         # "EXECUTED", "BLOCKED_BY_POLICY", "TERMINATED_BY_KERNEL"
    latency_ms: float
    output: Optional[str] = None
    violation_reason: Optional[str] = None
    forensic_hash: str = ""
    timestamp: float = field(default_factory=time.time)

    def generate_audit_hash(self, raw_payload: str) -> str:
        """Generates cryptographic proof of the execution event for Aegisora evidence logging."""
        record = f"{self.action_id}:{self.status}:{self.latency_ms}:{raw_payload}:{self.timestamp}"
        self.forensic_hash = hashlib.sha256(record.encode()).hexdigest()
        return self.forensic_hash
