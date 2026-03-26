# app/security/middleware.py

from __future__ import annotations
from langchain.tools import tool
from app.security.policy import audit_tool_call
from app.security.intent_auditor import IntentAuditor  #phase2
from app.tools.shell_tool import shell_exec
from app.tools.db_tool import query_user_record
from app.tools.http_tool import http_fetch
from app.tools.mail_tool import send_email


def build_guarded_tools(user_id: str, user_input: str):
    intent_auditor = IntentAuditor()  #语义审计器

    @tool
    def guarded_shell_exec(command: str) -> str:
        """审计后安全执行 shell 命令。"""
        intent_result = intent_auditor.audit(  #phase2
            user_input=user_input,  #用户的原始请求
            tool_name="shell_exec", #要调的工具
            tool_args={"command": command}, #参数
        )
        if not intent_result.allowed:  
            return (
                f"[BLOCKED by Intent Auditor] " 
                f"intent={intent_result.intent_label}, "
                f"risk={intent_result.risk_level}, "
                f"reason={intent_result.reason}"
            )

        decision = audit_tool_call("shell_exec", {"command": command}, user_id) #phase1
        if not decision.allowed:
            return f"[BLOCKED by Policy] shell_exec 被拦截：{decision.reason}"

        return shell_exec.invoke({"command": command})

    @tool
    def guarded_query_user_record(target_user_id: str) -> str:
        """审计后安全查询用户记录。"""
        intent_result = intent_auditor.audit(
            user_input=user_input,
            tool_name="query_user_record",
            tool_args={"user_id": target_user_id},
        )
        if not intent_result.allowed:
            return (
                f"[BLOCKED by Intent Auditor] "
                f"intent={intent_result.intent_label}, "
                f"risk={intent_result.risk_level}, "
                f"reason={intent_result.reason}"
            )

        decision = audit_tool_call("query_user_record", {"user_id": target_user_id}, user_id)
        if not decision.allowed:
            return f"[BLOCKED by Policy] query_user_record 被拦截：{decision.reason}"

        return query_user_record.invoke({"user_id": target_user_id})

    @tool
    def guarded_http_fetch(url: str) -> str:
        """审计后安全获取 URL。"""
        intent_result = intent_auditor.audit(
            user_input=user_input,
            tool_name="http_fetch",
            tool_args={"url": url},
        )
        if not intent_result.allowed:
            return (
                f"[BLOCKED by Intent Auditor] "
                f"intent={intent_result.intent_label}, "
                f"risk={intent_result.risk_level}, "
                f"reason={intent_result.reason}"
            )

        decision = audit_tool_call("http_fetch", {"url": url}, user_id)
        if not decision.allowed:
            return f"[BLOCKED by Policy] http_fetch 被拦截：{decision.reason}"

        return http_fetch.invoke({"url": url})

    @tool
    def guarded_send_email(to: str, subject: str, body: str) -> str:
        """审计后安全发送电子邮件。"""
        intent_result = intent_auditor.audit(
            user_input=user_input,
            tool_name="send_email",
            tool_args={"to": to, "subject": subject, "body": body},
        )
        if not intent_result.allowed:
            return (
                f"[BLOCKED by Intent Auditor] "
                f"intent={intent_result.intent_label}, "
                f"risk={intent_result.risk_level}, "
                f"reason={intent_result.reason}"
            )

        decision = audit_tool_call(
            "send_email",
            {"to": to, "subject": subject, "body": body},
            user_id,
        )
        if not decision.allowed:
            return f"[BLOCKED by Policy] send_email 被拦截：{decision.reason}"

        return send_email.invoke({"to": to, "subject": subject, "body": body})

    return [
        guarded_shell_exec,
        guarded_query_user_record,
        guarded_http_fetch,
        guarded_send_email,
    ]