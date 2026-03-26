# app/security/permission_guard.py  权限审计

from dataclasses import dataclass
@dataclass
class PermissionDecision:
    allowed: bool
    reason: str


ROLE_TOOL_POLICY = {
    "user_1": {
        "shell_exec",
        "query_user_record",
        "http_fetch",
        "send_email",
    },
    "user_2": {
        "shell_exec",
        "query_user_record",
        "http_fetch",
        "send_email",
    },
    "admin": {
        "shell_exec",
        "query_user_record",
        "http_fetch",
        "send_email",
    },
}


def check_tool_permission(user_id: str, tool_name: str) -> PermissionDecision:
    allowed_tools = ROLE_TOOL_POLICY.get(user_id)

    if allowed_tools is None:
        return PermissionDecision(False, f"未知用户或未配置权限: {user_id}")

    if tool_name not in allowed_tools:
        return PermissionDecision(False, f"用户 {user_id} 无权使用工具: {tool_name}")

    return PermissionDecision(True, "权限检查通过")