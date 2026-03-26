from urllib.parse import urlparse #把一个完整 URL 拆成结构化字段 只需要hostname
from langchain.tools import tool

INTERNAL_HOSTS = {"127.0.0.1", "localhost", "169.254.169.254"}
#纵深防御

@tool
def http_fetch(url: str) -> str:
    """
    获取指定 URL 的内容（模拟网络请求）。

    该工具用于模拟访问外部网页或接口，
    适用于需要获取网络资源的任务。
    """
    parsed = urlparse(url)
    host = parsed.hostname or "" #提取hostname=host
    if host in INTERNAL_HOSTS:
        return f"[SIMULATION BLOCK] Potential SSRF targ et: {url}"
    return f"[SIMULATION OK] Fetched external URL: {url}"