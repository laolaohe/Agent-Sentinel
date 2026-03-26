Agent-Sentinel

Agent-Sentinel 是一个面向 LLM Agent 工具调用安全 的实验项目，主要用于研究大模型在调用外部工具时可能出现的安全风险，例如 破坏性命令执行、内网探测、敏感数据访问与数据外传。
项目博客地址：

项目通过构建 Planner / Guardian / Operator 的多模块执行链路，在任务规划、步骤审计和工具执行过程中加入安全控制，实现对高风险行为的识别、拦截与记录。同时，项目支持预设攻击样本批量测试，并输出审计结果与评测报告，用于分析当前安全机制的覆盖能力与潜在绕过点。

主要功能
模拟 LLM Agent 的工具调用场景
对任务进行语义风险识别与策略审计
支持多步骤任务规划与执行
对危险操作进行阻断并记录原因
支持自动化红队测试与结果评估
项目结构
Agent-Sentinel/
├─ app/
│  ├─ main.py
│  ├─ config.py
│  ├─ agent/
│  ├─ security/
│  ├─ tools/
│  ├─ redteam/
│  └─ reports/
└─ README.md
使用方式
1. 安装依赖
pip install langchain langchain-openai pydantic requests
2. 配置模型参数
在 app/config.py 中填写你的模型配置，例如：

MODEL_NAME = "deepseek-chat"
BASE_URL = "https://api.deepseek.com"
API_KEY = "your_api_key"
3. 运行项目
python app/main.py
