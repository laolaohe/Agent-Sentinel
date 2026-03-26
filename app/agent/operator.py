# app/agent/operator.py

from __future__ import annotations

import re
from typing import Any

from app.agent.state import (
    ActionProposal,
    ExecutionRecord,
    SessionState,
    TaskStep,
)
from app.tools.db_tool import query_user_record
from app.tools.http_tool import http_fetch
from app.tools.mail_tool import send_email
from app.tools.shell_tool import shell_exec
from app.tools.summarize_tool import summarize_content


class OperatorAgent:
    ALLOWED_TOOLS = {
        "shell_exec",
        "query_user_record",
        "http_fetch",
        "send_email",
        "summarize_content",
    }

    def __init__(self):
        self.tool_registry = {
            "shell_exec": self._run_shell_exec,
            "query_user_record": self._run_query_user_record,
            "http_fetch": self._run_http_fetch,
            "send_email": self._run_send_email,
            "summarize_content": self._run_summarize_content,
        }

    def propose_action(self, step: TaskStep, state: SessionState) -> ActionProposal:
        state.current_step_id = step.step_id

        raw_args = dict(step.tool_args)
        resolved_args = self.resolve_args(raw_args, state)

        action = ActionProposal(
            step_id=step.step_id,
            description=step.description,
            tool_name=step.tool_name,
            raw_args=raw_args,
            resolved_args=resolved_args,
            execution_strategy="single_call",
            rationale="deterministic operator proposal",
            status="proposed",
        )

        state.action_proposals[step.step_id] = action
        return action

    def revise_action(self, step: TaskStep, state: SessionState, revised_action: dict[str, Any]) -> ActionProposal:
        raw_args = dict(revised_action.get("raw_args", step.tool_args))
        resolved_args = dict(revised_action.get("resolved_args", self.resolve_args(raw_args, state)))
        tool_name = str(revised_action.get("tool_name", step.tool_name))
        description = str(revised_action.get("description", step.description))
        execution_strategy = str(revised_action.get("execution_strategy", "single_call"))
        rationale = str(revised_action.get("rationale", "guardian revised action"))

        action = ActionProposal(
            step_id=step.step_id,
            description=description,
            tool_name=tool_name,
            raw_args=raw_args,
            resolved_args=resolved_args,
            execution_strategy=execution_strategy,
            rationale=rationale,
            status="proposed",
        )

        state.action_proposals[step.step_id] = action
        return action

    def resolve_args(self, tool_args: dict[str, Any], state: SessionState) -> dict[str, Any]:
        resolved: dict[str, Any] = {}

        for key, value in tool_args.items():
            if isinstance(value, str):
                resolved[key] = self._resolve_placeholders(value, state)
            else:
                resolved[key] = value

        return resolved

    def execute_action(self, action: ActionProposal, state: SessionState) -> ExecutionRecord:
        state.current_step_id = action.step_id

        runner = self.tool_registry.get(action.tool_name)
        if runner is None:
            action.status = "failed"
            return ExecutionRecord(
                step_id=action.step_id,
                tool_name=action.tool_name,
                raw_args=action.raw_args,
                resolved_args=action.resolved_args,
                output="",
                status="failed",
                approved_by_guardian=True,
                error=f"未知工具: {action.tool_name}",
            )

        try:
            output = runner(action.resolved_args)
            action.status = "executed"

            return ExecutionRecord(
                step_id=action.step_id,
                tool_name=action.tool_name,
                raw_args=action.raw_args,
                resolved_args=action.resolved_args,
                output=output,
                status="success",
                approved_by_guardian=True,
                error="",
            )
        except Exception as e:
            action.status = "failed"
            return ExecutionRecord(
                step_id=action.step_id,
                tool_name=action.tool_name,
                raw_args=action.raw_args,
                resolved_args=action.resolved_args,
                output="",
                status="failed",
                approved_by_guardian=True,
                error=f"执行异常: {e}",
            )

    def _resolve_placeholders(self, text: str, state: SessionState) -> str:
        pattern = r"\{\{step_(\d+)\.output\}\}"

        def replacer(match: re.Match) -> str:
            step_id = int(match.group(1))
            return state.step_outputs.get(step_id, f"[MISSING_OUTPUT_STEP_{step_id}]")

        return re.sub(pattern, replacer, text)

    def _run_shell_exec(self, args: dict[str, Any]) -> str:
        return shell_exec.invoke({"command": args["command"]})

    def _run_query_user_record(self, args: dict[str, Any]) -> str:
        return query_user_record.invoke({"user_id": args["user_id"]})

    def _run_http_fetch(self, args: dict[str, Any]) -> str:
        return http_fetch.invoke({"url": args["url"]})

    def _run_send_email(self, args: dict[str, Any]) -> str:
        return send_email.invoke(
            {
                "to": args["to"],
                "subject": args["subject"],
                "body": args["body"],
            }
        )

    def _run_summarize_content(self, args: dict[str, Any]) -> str:
        return summarize_content.invoke({"content": args["content"]})