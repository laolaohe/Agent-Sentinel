from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import re


@dataclass
class IntentAuditResult:
    allowed: bool #是否放行
    intent_label: str #意图类别
    risk_level: str #风险等级
    reason: str #解释
    signals: dict[str, Any] = field(default_factory=dict)  #返回一份结构化结果。


class IntentAuditor:
    """
    Phase 2: Semantic Intent Auditor
    负责识别用户请求和工具调用背后的真实任务意图，而不仅仅依赖显式规则匹配。
    """
    #出现语义说明要进行破坏性操作
    #删除
    DELETE_KEYWORDS = [
        "删除", "清空", "移除", "擦除", "销毁", "删掉", "全部删掉",
        "delete", "remove", "wipe", "erase", "destroy", "unlink", "find -delete",
    ]
    #规避检测
    EVASION_KEYWORDS = [
        "不要直接使用我常见提到的那种写法",
        "不要用常见写法",
        "换一种写法",
        "别直接写",
        "绕过",
        "规避",
        "不要使用常见",
        "不要被发现",
        "不要用 rm -rf",
        "avoid detection",
        "bypass",
        "not the usual way",
    ]
    #敏感数据
    SENSITIVE_KEYWORDS = [
        "user_", "用户", "账号", "工资", "salary", "email", "邮箱",
        "token", "secret", "password", "profile", "record", "数据库", "记录",
        "admin", "内部数据", "隐私", "个人信息",
    ]
    #可能出现数据外传
    TRANSFORM_KEYWORDS = [
        "整理", "摘要", "总结", "概括", "提炼", "压缩", "汇总",
        "summarize", "summary", "organize", "extract", "condense",
    ]
    #外传风险
    SEND_KEYWORDS = [
        "发送", "发给", "发到", "转发", "邮件", "邮箱", "发送到",
        "send", "email", "mail", "forward", "share",
    ]
    #SSRF风险
    INTERNAL_HOST_KEYWORDS = [
        "127.0.0.1",
        "localhost",
        "169.254.169.254",
    ]

    def audit(self, user_input: str, tool_name: str, tool_args: dict[str, Any]) -> IntentAuditResult:
        signals = self.collect_signals(user_input=user_input, tool_name=tool_name, tool_args=tool_args)
        intent = self.classify_intent(signals)
        risk = self.assess_risk(intent, signals)
        decision = self.make_decision(intent, risk)
        reason = self.build_reason(intent, signals)

        return IntentAuditResult(
            allowed=decision,
            intent_label=intent,
            risk_level=risk,
            reason=reason,
            signals=signals,
        )

    def collect_signals(self, user_input: str, tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        text = (user_input or "").lower()  #转小写
        tool_name = (tool_name or "").lower()
        args_text = str(tool_args).lower()  #工具生成的参数

        has_delete_intent = self._contains_any(text, self.DELETE_KEYWORDS) or self._contains_any(args_text, self.DELETE_KEYWORDS) #有没有删除语义
        has_evasion_hint = self._contains_any(text, self.EVASION_KEYWORDS)#有没有规则避免语义
        has_sensitive_access = self._contains_any(text, self.SENSITIVE_KEYWORDS) #查询数据
        has_transform_step = self._contains_any(text, self.TRANSFORM_KEYWORDS) #数据外传
        has_external_send = self._contains_any(text, self.SEND_KEYWORDS) #外传风险
        has_internal_probe = self._contains_any(text, self.INTERNAL_HOST_KEYWORDS) or self._contains_any(args_text, self.INTERNAL_HOST_KEYWORDS) #SSRF

        email_targets = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text)
        shell_delete_like = False

        if tool_name == "shell_exec":
            suspicious_shell_tokens = [
                "rm ", "find ", "-delete", "unlink", "rmdir", "del ", "erase ","delete",
            ]
            shell_delete_like = any(token in args_text for token in suspicious_shell_tokens) #查看工具参数有没有删除

        # 基于工具类型补信号
        if tool_name == "query_user_record":
            has_sensitive_access = True #调用查询工具查用户记录天然就是敏感访问

        if tool_name == "send_email":
            has_external_send = True #调用发送邮件工具

        if tool_name == "http_fetch" and has_internal_probe:
            has_internal_probe = True #命中内部

        return {
            "tool_name": tool_name,
            "tool_args": tool_args,
            "email_targets": email_targets,
            "has_delete_intent": has_delete_intent,
            "has_evasion_hint": has_evasion_hint,
            "has_sensitive_access": has_sensitive_access,
            "has_transform_step": has_transform_step,
            "has_external_send": has_external_send,
            "has_internal_probe": has_internal_probe,
            "shell_delete_like": shell_delete_like,
            "raw_user_input": user_input,
        }

    def classify_intent(self, signals: dict[str, Any]) -> str:
        if signals["has_internal_probe"]: #如果调用工具internal 并且 语义存在内网
            return "internal_probe"

        if signals["has_delete_intent"] or signals["shell_delete_like"]: #工具参数有删除或者userprompt有删除
            return "destructive_action"

        if (
            signals["has_sensitive_access"] 
            and signals["has_transform_step"]
            and signals["has_external_send"] #同时满足查敏感数据 + 做摘要/整理 + 发出去  ==》链式语义识别
        ):
            return "data_exfiltration"

        if signals["has_sensitive_access"]:
            return "sensitive_data_access" #查敏感数据

        return "benign_task"  #都没有返回正常

    def assess_risk(self, intent: str, signals: dict[str, Any]) -> str:
        if intent == "internal_probe":
            return "high"

        if intent == "destructive_action": #有删除意图return high
            if signals["has_evasion_hint"]: #有规避+删除意图 return critical
                return "critical"
            return "high"

        if intent == "data_exfiltration": #总结数据外传
            return "critical"

        if intent == "sensitive_data_access": #查询敏感数据
            return "medium"

        return "low"

    def make_decision(self, intent: str, risk: str) -> bool:
        # Phase 2 当前策略：
        # high / critical 直接 block
        # medium 先允许交给 Phase 1 继续审计
        return risk not in ("high", "critical")

    def build_reason(self, intent: str, signals: dict[str, Any]) -> str:
        if intent == "internal_probe":
            return "检测到访问本机/内网/云 metadata 的语义意图，疑似 SSRF 或内网探测。"

        if intent == "destructive_action":
            if signals["has_evasion_hint"]:
                return "检测到删除/破坏性操作意图，且包含规避常见写法的绕过提示。"
            return "检测到删除/破坏性操作意图。"

        if intent == "data_exfiltration":
            return "检测到敏感数据查询 + 内容整理 + 对外发送的数据外传链。"

        if intent == "sensitive_data_access":
            return "检测到敏感数据访问意图。"

        return "未发现明显高风险语义意图。"

    @staticmethod
    def _contains_any(text: str, keywords: list[str]) -> bool:
        return any(keyword.lower() in text for keyword in keywords)