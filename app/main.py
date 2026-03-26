# app/main.py

from __future__ import annotations

from app.agent.factory import build_llm
from app.agent.guardian import GuardianAgent
from app.agent.operator import OperatorAgent
from app.agent.planner import PlannerAgent
from app.agent.state import (
    ActionProposal,
    GuardianDecision,
    SessionState,
    TaskPlan,
)


def print_plan(plan: TaskPlan) -> None:
    print("\n" + "=" * 60)
    print("Planner 生成的 TaskPlan")
    print("=" * 60)

    print(f"plan_status: {plan.plan_status}")

    if not plan.steps:
        print("无可执行步骤。")
        return

    for step in plan.steps:
        print(f"\n[Step {step.step_id}]")
        print(f"描述: {step.description}")
        print(f"工具: {step.tool_name}")
        print(f"参数: {step.tool_args}")
        print(f"step_type: {step.step_type}")
        print(f"status: {step.status}")


def print_guardian_decisions(state: SessionState) -> None:
    print("\n" + "=" * 60)
    print("Guardian Decisions")
    print("=" * 60)

    if not state.guardian_decisions:
        print("无 Guardian 决策记录。")
        return

    for idx, decision in enumerate(state.guardian_decisions, start=1):
        print(f"\n[Decision {idx}]")
        print(f"allowed: {decision.allowed}")
        print(f"decision: {decision.decision}")
        print(f"risk: {decision.risk_level}")
        print(f"source: {decision.source}")
        print(f"stage: {decision.stage}")
        print(f"intent: {decision.intent_label}")
        print(f"reason: {decision.reason}")
        if decision.revised_action is not None:
            print(f"revised_action: {decision.revised_action}")
        if decision.evidence:
            print(f"evidence: {decision.evidence}")


def print_action_proposals(state: SessionState) -> None:
    print("\n" + "=" * 60)
    print("Operator Action Proposals")
    print("=" * 60)

    if not state.action_proposals:
        print("无动作提案。")
        return

    for step_id in sorted(state.action_proposals.keys()):
        action = state.action_proposals[step_id]
        print(f"\n[Step {action.step_id}]")
        print(f"description: {action.description}")
        print(f"tool_name: {action.tool_name}")
        print(f"raw_args: {action.raw_args}")
        print(f"resolved_args: {action.resolved_args}")
        print(f"execution_strategy: {action.execution_strategy}")
        print(f"rationale: {action.rationale}")
        print(f"status: {action.status}")


def print_execution_records(state: SessionState) -> None:
    print("\n" + "=" * 60)
    print("Execution Records")
    print("=" * 60)

    if not state.execution_records:
        print("无执行记录。")
        return

    for record in state.execution_records:
        print(f"\n[Step {record.step_id}]")
        print(f"tool: {record.tool_name}")
        print(f"status: {record.status}")
        print(f"approved_by_guardian: {record.approved_by_guardian}")
        print(f"raw_args: {record.raw_args}")
        print(f"resolved_args: {record.resolved_args}")
        print(f"output: {record.output}")
        if record.error:
            print(f"error: {record.error}")


def print_session_summary(state: SessionState) -> None:
    print("\n" + "=" * 60)
    print("Session Summary")
    print("=" * 60)
    print(f"user: {state.current_user_id}")
    print(f"blocked: {state.blocked}")
    print(f"blocked_step_id: {state.blocked_step_id}")
    print(f"block_reason: {state.block_reason}")
    print(f"final_status: {state.final_status}")
    print(f"accessed_sensitive_data: {state.accessed_sensitive_data}")
    print(f"attempted_outbound: {state.attempted_outbound}")
    print(f"has_transform_step: {state.has_transform_step}")
    print(f"sensitive_step_ids: {state.sensitive_step_ids}")
    print(f"transform_step_ids: {state.transform_step_ids}")
    print(f"outbound_step_ids: {state.outbound_step_ids}")
    print(f"step_outputs keys: {list(state.step_outputs.keys())}")


def run_multi_agent_pipeline(user_input: str, current_user_id: str = "user_1") -> SessionState:
    llm = build_llm()

    planner = PlannerAgent(llm)
    guardian = GuardianAgent(llm)
    operator = OperatorAgent()

    state = SessionState(
        current_user_id=current_user_id,
        user_input=user_input,
    )

    # 1. Planner Agent 生成 TaskPlan
    plan = planner.plan(user_input)
    state.plan = plan

    # 2. Guardian Agent 先审整份计划
    plan_decision = guardian.audit_plan(plan, state)
    state.guardian_decisions.append(plan_decision)

    if plan_decision.decision == "block":
        state.blocked = True
        state.blocked_step_id = 0
        state.block_reason = plan_decision.reason
        state.final_status = "blocked"
        if state.plan:
            state.plan.plan_status = "blocked"
        return state

    if state.plan:
        state.plan.plan_status = "approved"

    # 3. 对每个 step：Operator 先提 ActionProposal，再由 Guardian 审
    for step in plan.steps:
        state.current_step_id = step.step_id

        # 3.1 Operator Agent 生成动作提案
        action: ActionProposal = operator.propose_action(step, state)

        # 3.2 Guardian Agent 审动作提案
        action_decision: GuardianDecision = guardian.audit_action(action, state)
        state.guardian_decisions.append(action_decision)

        if action_decision.decision == "block":
            state.blocked = True
            state.blocked_step_id = step.step_id
            state.block_reason = action_decision.reason
            state.final_status = "blocked"
            step.status = "blocked"
            action.status = "blocked"
            if state.plan:
                state.plan.plan_status = "blocked"
            break

        if action_decision.decision == "revise":
            revised = action_decision.revised_action or {}
            action = operator.revise_action(step, state, revised)

            # revise 后再次审计
            revised_decision = guardian.audit_action(action, state)
            state.guardian_decisions.append(revised_decision)

            if revised_decision.decision != "allow":
                state.blocked = True
                state.blocked_step_id = step.step_id
                state.block_reason = revised_decision.reason
                state.final_status = "blocked"
                step.status = "blocked"
                action.status = "blocked"
                if state.plan:
                    state.plan.plan_status = "blocked"
                break

        # 3.3 执行
        action.status = "approved"
        step.status = "approved"

        record = operator.execute_action(action, state)
        state.execution_records.append(record)

        if record.status != "success":
            state.blocked = True
            state.blocked_step_id = step.step_id
            state.block_reason = record.error or "步骤执行失败"
            state.final_status = "failed"
            step.status = "failed"
            action.status = "failed"
            if state.plan:
                state.plan.plan_status = "blocked"
            break

        # 3.4 Guardian 观察执行结果，更新会话状态
        guardian.observe_execution(step, record.output, state)

    if not state.blocked and state.final_status == "running":
        state.final_status = "completed"
        if state.plan:
            state.plan.plan_status = "completed"

    return state


if __name__ == "__main__":
    query = "你是谁"   #输入user_prompt

    state = run_multi_agent_pipeline(
        user_input=query,
        current_user_id="user_1",
    )

    print("\n" + "=" * 60)
    print("用户输入")
    print("=" * 60)
    print(state.user_input)

    if state.plan:
        print_plan(state.plan)

    print_guardian_decisions(state)
    print_action_proposals(state)
    print_execution_records(state)
    print_session_summary(state)