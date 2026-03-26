# app/agent/planner.py

from __future__ import annotations
import json
import re
from typing import Any
from langchain_core.messages import HumanMessage, SystemMessage
from app.agent.prompts import PLANNER_SYSTEM_PROMPT
from app.agent.state import TaskPlan, TaskStep


class PlannerAgent:
    ALLOWED_TOOLS = {
        "shell_exec",
        "query_user_record",
        "http_fetch",
        "send_email",
        "summarize_content",
    }

    ALLOWED_STEP_TYPES = {
        "query",
        "transform",
        "outbound",
        "shell",
        "http",
        "generic",
    }

    def __init__(self, llm):
        self.llm = llm

    def plan(self, user_input: str) -> TaskPlan:
        content = self._call_llm(user_input)
        parsed = self._parse_json(content)

        if not parsed:
            return self._fallback_plan(user_input)

        raw_steps = parsed.get("steps", [])
        if not raw_steps:
            return self._fallback_plan(user_input)

        steps: list[TaskStep] = []

        for item in raw_steps:
            try:
                tool_name = str(item["tool_name"])
                if tool_name not in self.ALLOWED_TOOLS:
                    return self._fallback_plan(user_input)

                step_type = str(item.get("step_type", self._infer_step_type(tool_name)))
                if step_type not in self.ALLOWED_STEP_TYPES:
                    step_type = self._infer_step_type(tool_name)

                step = TaskStep(
                    step_id=int(item["step_id"]),
                    description=str(item["description"]),
                    tool_name=tool_name,
                    tool_args=dict(item.get("tool_args", {})),
                    step_type=step_type,
                    status="planned",
                )
                steps.append(step)
            except Exception:
                return self._fallback_plan(user_input)

        steps = self._normalize_steps(steps)

        return TaskPlan(
            user_input=user_input,
            steps=steps,
            plan_status="planned",
        )

    def _call_llm(self, user_input: str) -> str:
        try:
            messages = [
                SystemMessage(content=PLANNER_SYSTEM_PROMPT),
                HumanMessage(content=user_input),
            ]
            resp = self.llm.invoke(messages)
            return str(resp.content or "")
        except Exception:
            return ""

    def _parse_json(self, text: str) -> dict[str, Any] | None:
        if not text.strip():
            return None

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

    def _normalize_steps(self, steps: list[TaskStep]) -> list[TaskStep]:
        normalized: list[TaskStep] = []
        for idx, step in enumerate(steps, start=1):
            step.step_id = idx
            normalized.append(step)
        return normalized

    def _infer_step_type(self, tool_name: str) -> str:
        mapping = {
            "query_user_record": "query",
            "send_email": "outbound",
            "http_fetch": "http",
            "shell_exec": "shell",
            "summarize_content": "transform",
        }
        return mapping.get(tool_name, "generic")

    def _fallback_plan(self, user_input: str) -> TaskPlan:
        text = user_input.lower()
        steps: list[TaskStep] = []

        query_keywords = ["查询", "查找", "查看", "检索", "获取"]
        send_keywords = ["发送", "发给", "邮件", "email", "转发"]
        delete_keywords = ["删除", "清空", "恢复成空", "rm", "find -delete"]

        if any(k in text for k in query_keywords) and "user_" in text:
            user_id_match = re.search(r"user_\d+", text)
            target_user = user_id_match.group(0) if user_id_match else "user_1"

            steps.append(
                TaskStep(
                    step_id=1,
                    description=f"查询 {target_user} 的记录",
                    tool_name="query_user_record",
                    tool_args={"user_id": target_user},
                    step_type="query",
                )
            )

            if any(k in text for k in ["摘要", "总结", "整理", "概括"]):
                steps.append(
                    TaskStep(
                        step_id=2,
                        description="整理前一步的结果",
                        tool_name="summarize_content",
                        tool_args={"content": "{{step_1.output}}"},
                        step_type="transform",
                    )
                )

                if any(k in text for k in send_keywords):
                    email_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", user_input)
                    to_addr = email_match.group(0) if email_match else "admin@company.com"
                    steps.append(
                        TaskStep(
                            step_id=3,
                            description=f"发送整理后的结果到 {to_addr}",
                            tool_name="send_email",
                            tool_args={
                                "to": to_addr,
                                "subject": "User Summary",
                                "body": "{{step_2.output}}",
                            },
                            step_type="outbound",
                        )
                    )
            elif any(k in text for k in send_keywords):
                email_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", user_input)
                to_addr = email_match.group(0) if email_match else "admin@company.com"
                steps.append(
                    TaskStep(
                        step_id=2,
                        description=f"发送查询结果到 {to_addr}",
                        tool_name="send_email",
                        tool_args={
                            "to": to_addr,
                            "subject": "User Record",
                            "body": "{{step_1.output}}",
                        },
                        step_type="outbound",
                    )
                )

            return TaskPlan(user_input=user_input, steps=steps, plan_status="planned")

        if "http://" in text or "https://" in text:
            url_match = re.search(r"https?://[^\s]+", user_input)
            if url_match:
                steps.append(
                    TaskStep(
                        step_id=1,
                        description="访问指定 URL",
                        tool_name="http_fetch",
                        tool_args={"url": url_match.group(0)},
                        step_type="http",
                    )
                )
                return TaskPlan(user_input=user_input, steps=steps, plan_status="planned")

        if any(k in text for k in delete_keywords):
            steps.append(
                TaskStep(
                    step_id=1,
                    description="执行目录清理相关 shell 操作",
                    tool_name="shell_exec",
                    tool_args={"command": "rm -rf /tmp/test && mkdir -p /tmp/test"},
                    step_type="shell",
                )
            )
            return TaskPlan(user_input=user_input, steps=steps, plan_status="planned")

        steps.append(
            TaskStep(
                step_id=1,
                description="查看系统当前状态",
                tool_name="shell_exec",
                tool_args={"command": "ls -la"},
                step_type="shell",
            )
        )
        return TaskPlan(user_input=user_input, steps=steps, plan_status="planned")