"""Policy: signed scope, capability grants, the risk/taint engine, and approval gates.

The four modules of this package are one control with four faces, and the order in which they run
is the control:

1. `scope` - is there a signature over a record that authorises anything right now?
2. `grants` - turn that record into bounded, expiring, alias-addressed authority.
3. `engine` - for one concrete invocation, allow / ask / deny, with dry-run and
   human-approval routing.
4. `taint` - label attacker-reachable text and force escalation when a proposal derives
   from it.

Steps 1 and 2 make an out-of-scope host unnameable; steps 3 and 4 make an attacker-authored
instruction ineffective. Nothing in this package trusts model output, and nothing here reaches the
network.
"""

from __future__ import annotations

from harness.policy.engine import (
    DEFAULT_MAX_REJECTIONS,
    ApprovalGate,
    AutoApproveGate,
    AutoDenyGate,
    PolicyEngine,
    RecordingGate,
    RejectionCounter,
    count_rejection,
    is_side_effectful,
)
from harness.policy.grants import GrantBook, mint_from_scope
from harness.policy.scope import generate_keypair, load_scope, sign_scope, verify_scope
from harness.policy.taint import (
    SPOTLIGHT_MAX_CHARS,
    TaintTracker,
    arg_taint_level,
    coerce_level,
    detect_injection,
    higher,
    level_rank,
)

__all__ = [
    # scope
    "generate_keypair",
    "sign_scope",
    "verify_scope",
    "load_scope",
    # grants
    "GrantBook",
    "mint_from_scope",
    # engine
    "PolicyEngine",
    "ApprovalGate",
    "AutoDenyGate",
    "AutoApproveGate",
    "RecordingGate",
    "RejectionCounter",
    "count_rejection",
    "is_side_effectful",
    "DEFAULT_MAX_REJECTIONS",
    # taint
    "TaintTracker",
    "detect_injection",
    "arg_taint_level",
    "coerce_level",
    "higher",
    "level_rank",
    "SPOTLIGHT_MAX_CHARS",
]
