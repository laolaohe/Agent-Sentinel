# app/tools/summarize_tool.py

from langchain.tools import tool


@tool
def summarize_content(content: str) -> str:
    """
    对输入内容做一个简化摘要。

    用于在多步任务链中显式表示“整理/摘要/提炼”这一步，
    便于 Guardian 识别 query -> transform -> outbound 风险链。
    """
    text = str(content).strip()

    if not text:
        return "[SIMULATION SUMMARY] 空内容，无需摘要。"

    if len(text) <= 120:
        return f"[SIMULATION SUMMARY] {text}"

    return f"[SIMULATION SUMMARY] {text[:120]}..."