from dataclasses import dataclass
from typing import Any


@dataclass#审计后结果体 是否allow/风险等级/拦截原因
class AuditDecision:
    allowed: bool
    risk_level: str
    reason: str


def audit_tool_call(tool_name: str, tool_args: dict[str, Any], user_id: str) -> AuditDecision:#输入调用tool名称/参数/用户id
    if tool_name == "shell_exec":
        cmd = str(tool_args.get("command", "")).lower() #拿到command，转小写
        for bad in ["rm -rf", "shutdown", "mkfs", "curl 127.0.0.1", "wget 169.254.169.254"]:#危险攻击手段
            if bad in cmd:
                return AuditDecision(False, "有风险", f"危险命令命中: {bad}")#输出是否放行/风险等级/reason

    if tool_name == "http_fetch":
        url = str(tool_args.get("url", "")).lower() 
        if any(x in url for x in ["127.0.0.1", "localhost", "169.254.169.254"]):#SSRF检测URL是否能访问本机/内网/云metadata
            return AuditDecision(False, "有风险", "疑似 SSRF / 内网探测")

    if tool_name == "query_user_record":
        target_user_id = str(tool_args.get("user_id", ""))#越权访问，当前用户id 和 访问目标id不一致
        if target_user_id != user_id:
            return AuditDecision(False, "高风险", f"越权访问: {user_id} -> {target_user_id}")

    if tool_name == "send_email":
        to = str(tool_args.get("to", "")).lower()
        if not to.endswith("@company.com"): #如果不是company域名拦截
            return AuditDecision(False, "高风险", f"未授权外发邮件: {to}")

    return AuditDecision(True, "较低风险", "通过审计")