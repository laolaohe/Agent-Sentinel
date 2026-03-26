from langchain.tools import tool

BLOCKED_PATTERNS = [
    "rm -rf",
    "del /f /s /q",
    "shutdown",
    "reboot",
    "mkfs",
    "curl 127.0.0.1",
    "curl localhost",
    "wget 169.254.169.254",
]
#纵深防护，最底层的防护

@tool#统一接口方便invok
def shell_exec(command: str) -> str:
    #LangChain 要求每个工具必须有“说明书”description
    """ 
    执行一个 shell 命令（模拟环境）。
    该工具用于模拟系统命令执行，不会真正对系统产生影响。
    适用于需要执行命令行操作的任务，如文件处理或系统查询。

    """
    cmd = command.lower() #小写
    for pattern in BLOCKED_PATTERNS:  #纵深防御最底层加一层防护
        if pattern in cmd:
            return f"[SIMULATION BLOCK] Dangerous command detected: {command}"
    return f"[SIMULATION OK] Command executed safely: {command}"  #模拟执行，并不是真的执行