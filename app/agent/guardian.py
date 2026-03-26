# app/agent/guardian.py
from __future__ import annotations
import json
import re
from typing import Any
from langchain_core.messages import HumanMessage, SystemMessage
from app.agent.prompts import GUARDIAN_SYSTEM_PROMPT
from app.agent.state import (
    ActionProposal,
    GuardianDecision,
    SessionState,
    TaskPlan,
    TaskStep,
)
from app.security.intent_auditor import IntentAuditor
from app.security.permission_guard import check_tool_permission
from app.security.policy import audit_tool_call


class GuardianAgent:
    def __init__(self, llm):
        self.llm = llm
        self.intent_auditor = IntentAuditor()

    def audit_plan(self, plan: TaskPlan, state: SessionState) -> GuardianDecision:
        # 1. 规则/结构级粗审
        structure_block = self._plan_structure_guard(plan)
        if structure_block is not None:
            return structure_block

        # 2. LLM 计划审计
        llm_decision = self._llm_audit_plan(plan, state)
        if llm_decision.decision == "block":
            return llm_decision

        return GuardianDecision(
            allowed=True,
            decision="allow",
            risk_level="low",
            reason="计划级 Guardian 审计通过",
            source="llm_guard",
            intent_label="plan_allowed",
            stage="plan",
        )

    def audit_action(self, action: ActionProposal, state: SessionState) -> GuardianDecision:
        # 1. 权限层
        perm = check_tool_permission(state.current_user_id, action.tool_name)
        if not perm.allowed:
            return GuardianDecision(
                allowed=False,
                decision="block",
                risk_level="high",
                reason=perm.reason,
                source="permission_guard",
                intent_label="permission_denied",
                stage="permission",
                evidence={"tool_name": action.tool_name, "user_id": state.current_user_id},
            )

        # 2. 会话级链路审计
        session_decision = self._session_chain_guard(action, state)
        if session_decision is not None:
            return session_decision

        # 3. 语义级审计（Phase 2）
        intent_result = self.intent_auditor.audit(
            user_input=state.user_input,
            tool_name=action.tool_name,
            tool_args=action.resolved_args,
        )
        if not intent_result.allowed:
            return GuardianDecision(
                allowed=False,
                decision="block",
                risk_level=intent_result.risk_level,
                reason=intent_result.reason,
                source="intent_guard",
                intent_label=intent_result.intent_label,
                stage="action",
                evidence=intent_result.signals,
            )

        # 4. 规则层（Phase 1）
        policy_result = audit_tool_call(action.tool_name, action.resolved_args, state.current_user_id)
        if not policy_result.allowed:
            return GuardianDecision(
                allowed=False,
                decision="block",
                risk_level=policy_result.risk_level,
                reason=policy_result.reason,
                source="policy_guard",
                intent_label="policy_blocked",
                stage="action",
                evidence={"resolved_args": action.resolved_args},
            )

        # 5. LLM 动作审计
        llm_decision = self._llm_audit_action(action, state)
        if llm_decision.decision in ("block", "revise"):
            return llm_decision

        return GuardianDecision(
            allowed=True,
            decision="allow",
            risk_level="low",
            reason="动作级 Guardian 审计通过",
            source="llm_guard",
            intent_label="action_allowed",
            stage="action",
            evidence={"tool_name": action.tool_name},
        )

    def observe_execution(self, step: TaskStep, output: str, state: SessionState) -> None:
        state.current_step_id = step.step_id
        state.step_outputs[step.step_id] = output
        step.status = "executed"

        if step.tool_name == "query_user_record":
            state.accessed_sensitive_data = True
            if step.step_id not in state.sensitive_step_ids:
                state.sensitive_step_ids.append(step.step_id)

        if step.tool_name in ("send_email", "http_fetch"):
            state.attempted_outbound = True
            if step.step_id not in state.outbound_step_ids:
                state.outbound_step_ids.append(step.step_id)

        if step.tool_name == "summarize_content":
            state.has_transform_step = True
            if step.step_id not in state.transform_step_ids:
                state.transform_step_ids.append(step.step_id)

    def _plan_structure_guard(self, plan: TaskPlan) -> GuardianDecision | None:
        if not plan.steps:
            return GuardianDecision(
                allowed=False,
                decision="block",
                risk_level="medium",
                reason="Planner 生成了空计划。",
                source="policy_guard",
                intent_label="empty_plan",
                stage="plan",
            )

        has_query = any(step.step_type == "query" for step in plan.steps)
        has_outbound = any(step.step_type == "outbound" for step in plan.steps)

        if has_query and has_outbound:
            return GuardianDecision(
                allowed=False,
                decision="block",
                risk_level="critical",
                reason="检测到计划级危险链：整份计划同时包含敏感查询与外发步骤。",
                source="session_guard",
                intent_label="plan_data_exfiltration",
                stage="plan",
                evidence={
                    "step_types": [step.step_type for step in plan.steps],
                    "tools": [step.tool_name for step in plan.steps],
                },
            )
        return None

    def _session_chain_guard(self, action: ActionProposal, state: SessionState) -> GuardianDecision | None:
        args_text = str(action.resolved_args)
        references_previous_output = any(
            marker in args_text for marker in ["step_1", "step_2", "step_3", "{{step_"]
        )

        if state.accessed_sensitive_data and action.tool_name in ("send_email", "http_fetch"):
            reason = "检测到会话级数据外传链：此前已访问敏感数据，当前动作尝试对外发送/传输。"
            if references_previous_output:
                reason = "检测到高置信度会话级数据外传链：当前外发动作显式引用了前序输出，且此前已访问敏感数据。"

            return GuardianDecision(
                allowed=False,
                decision="block",
                risk_level="critical",
                reason=reason,
                source="session_guard",
                intent_label="session_data_exfiltration",
                stage="session",
                evidence={
                    "accessed_sensitive_data": state.accessed_sensitive_data,
                    "resolved_args": action.resolved_args,
                    "sensitive_step_ids": list(state.sensitive_step_ids),
                    "references_previous_output": references_previous_output,
                },
            )
        return None

    def _llm_audit_plan(self, plan: TaskPlan, state: SessionState) -> GuardianDecision:
        payload = {
            "user_input": state.user_input,
            "plan": {
                "steps": [
                    {
                        "step_id": s.step_id,
                        "description": s.description,
                        "tool_name": s.tool_name,
                        "tool_args": s.tool_args,
                        "step_type": s.step_type,
                    }
                    for s in plan.steps
                ]
            },
        }

        resp_text = self._call_guardian_llm(payload) #调用LLM
        parsed = self._parse_guardian_json(resp_text)

        if not parsed:
            return GuardianDecision(
                allowed=True,
                decision="allow",
                risk_level="medium",
                reason="Guardian LLM 计划审计解析失败，退化为放行并交给后续硬约束。",
                source="llm_guard",
                intent_label="llm_parse_failed",
                stage="plan",
            )

        decision = str(parsed.get("decision", "allow"))
        risk = str(parsed.get("risk_level", "medium"))
        reason = str(parsed.get("reason", "Guardian plan audit"))
        intent_label = str(parsed.get("intent_label", "unknown"))

        return GuardianDecision(
            allowed=(decision == "allow"),
            decision=decision,
            risk_level=risk,
            reason=reason,
            source="llm_guard",
            intent_label=intent_label,
            revised_action=parsed.get("revised_action"),
            stage="plan",
            evidence={"llm_payload": payload},
        )

    def _llm_audit_action(self, action: ActionProposal, state: SessionState) -> GuardianDecision:
        payload = {
            "user_input": state.user_input,
            "session_flags": {
                "accessed_sensitive_data": state.accessed_sensitive_data,
                "attempted_outbound": state.attempted_outbound,
                "has_transform_step": state.has_transform_step,
            },
            "action": {
                "step_id": action.step_id,
                "description": action.description,
                "tool_name": action.tool_name,
                "raw_args": action.raw_args,
                "resolved_args": action.resolved_args,
                "execution_strategy": action.execution_strategy,
                "rationale": action.rationale,
            },
        }

        resp_text = self._call_guardian_llm(payload)
        parsed = self._parse_guardian_json(resp_text)

        if not parsed:
            return GuardianDecision(
                allowed=True,
                decision="allow",
                risk_level="medium",
                reason="Guardian LLM 动作审计解析失败，退化为放行并交给其他硬约束。",
                source="llm_guard",
                intent_label="llm_parse_failed",
                stage="action",
            )

        decision = str(parsed.get("decision", "allow"))
        risk = str(parsed.get("risk_level", "medium"))
        reason = str(parsed.get("reason", "Guardian action audit"))
        intent_label = str(parsed.get("intent_label", "unknown"))

        return GuardianDecision(
            allowed=(decision == "allow"),
            decision=decision,
            risk_level=risk,
            reason=reason,
            source="llm_guard",
            intent_label=intent_label,
            revised_action=parsed.get("revised_action"),
            stage="action",
            evidence={"llm_payload": payload},
        )

    def _call_guardian_llm(self, payload: dict[str, Any]) -> str:
        messages = [
            SystemMessage(content=GUARDIAN_SYSTEM_PROMPT),
            HumanMessage(content=json.dumps(payload, ensure_ascii=False)),
        ]
        resp = self.llm.invoke(messages)
        return str(resp.content or "")

    def _parse_guardian_json(self, text: str) -> dict[str, Any] | None: #LLM回复JSON转格式
        try:
            return json.loads(text)
        except Exception:
            pass

        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None

        try:
            return json.loads(match.group(0))
        except Exception:
            return None