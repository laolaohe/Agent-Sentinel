from langchain.tools import tool


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """
    发送邮件（模拟环境）。
    用于向指定邮箱发送邮件，包含主题和正文内容。
    适用于通知、报告发送等任务。
    """
    if not to.lower().endswith("@company.com"): #判断域名是否为company 纵深防御
        return f"[SIMULATION BLOCK] Unauthorized recipient domain: {to}"
    return f"[SIMULATION OK] Email sent to {to} with subject: {subject}"