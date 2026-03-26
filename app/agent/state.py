# app/agent/state.py

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TaskStep:
    step_id: int
    description: str
    tool_name: str
    tool_args: dict[str, Any]
    step_type: str = "generic"   # query / transform / outbound / shell / http / generic
    status: str = "planned"      # planned / approved / blocked / executed / failed


@dataclass
class TaskPlan:
    user_input: str
    steps: list[TaskStep] = field(default_factory=list)
    plan_status: str = "planned"   # planned / approved / blocked / completed


@dataclass
class ActionProposal:
    step_id: int
    description: str
    tool_name: str
    raw_args: dict[str, Any]
    resolved_args: dict[str, Any]
    execution_strategy: str = "single_call"   # single_call / retry_once / read_only_fallback
    rationale: str = ""
    status: str = "proposed"                  # proposed / approved / blocked / executed / failed


@dataclass
class GuardianDecision:
    allowed: bool
    decision: str                 # allow / block / revise
    risk_level: str               # low / medium / high / critical
    reason: str
    source: str                   # llm_guard / intent_guard / policy_guard / session_guard / permission_guard
    intent_label: str = "unknown"
    revised_action: dict[str, Any] | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    stage: str = "step"           # plan / action / session / permission


@dataclass
class ExecutionRecord:
    step_id: int
    tool_name: str
    raw_args: dict[str, Any]
    resolved_args: dict[str, Any]
    output: str = ""
    status: str = "pending"       # pending / success / blocked / failed
    approved_by_guardian: bool = False
    error: str = ""


@dataclass
class SessionState:
    current_user_id: str
    user_input: str
    plan: TaskPlan | None = None

    guardian_decisions: list[GuardianDecision] = field(default_factory=list)
    execution_records: list[ExecutionRecord] = field(default_factory=list)

    # 执行过程缓存
    step_outputs: dict[int, str] = field(default_factory=dict)
    action_proposals: dict[int, ActionProposal] = field(default_factory=dict)

    # 会话级安全信号
    accessed_sensitive_data: bool = False
    attempted_outbound: bool = False
    has_transform_step: bool = False

    sensitive_step_ids: list[int] = field(default_factory=list)
    outbound_step_ids: list[int] = field(default_factory=list)
    transform_step_ids: list[int] = field(default_factory=list)

    blocked: bool = False
    blocked_step_id: int | None = None
    block_reason: str = ""

    current_step_id: int | None = None
    final_status: str = "running"   # running / completed / blocked / failed