from __future__ import annotations

import json
import os

# 这里导入的是你 Phase 3 的主流程函数。
# 它应该接收 user_input / current_user_id，返回 SessionState。
from app.main import run_multi_agent_pipeline

from app.redteam.payloads import (
    get_default_payloads,
    # 如果你后面想按类别跑，也可以直接导入这些筛选函数
    # filter_payloads_by_category,
    # filter_payloads_by_severity,
    # filter_payloads_by_tags,
)
from app.redteam.runner import RedTeamRunner
from app.redteam.evaluator import RedTeamEvaluator


def ensure_reports_dir(path: str = "reports") -> None:
    """
    确保报告输出目录存在。
    """
    os.makedirs(path, exist_ok=True)


def save_json(data, path: str) -> None:
    """
    通用 JSON 保存函数。
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main():
    """
    Phase 4 红队测试主入口。

    整体流程：
    1. 读取 payload 样本集
    2. 初始化 runner / evaluator
    3. 批量运行 payload
    4. 汇总评测结果
    5. 生成 JSON / Markdown 报告
    6. 在控制台输出简要统计
    """

    # ============================================================
    # 1. 准备 payload 样本集
    # ============================================================
    # 默认直接取全量样本集。
    # 后面如果你想只测某些类别，可以在这里换成过滤后的 payload 列表。
    payloads = get_default_payloads()

    # 例子：只测某些类别（现在先注释掉）
    # payloads = filter_payloads_by_category(
    #     get_default_payloads(),
    #     ["data_exfiltration", "internal_probe"]
    # )

    # ============================================================
    # 2. 初始化 runner 和 evaluator
    # ============================================================
    # runner 负责：
    # - 调用 Phase 3 主流程跑每条 payload
    # - 收集 SessionState
    # - 提取成标准化 RedTeamRunResult
    runner = RedTeamRunner(
        pipeline_callable=run_multi_agent_pipeline,
        current_user_id="user_1",
    )

    # evaluator 负责：
    # - 对批量运行结果做统计
    # - 生成结构化评测结果
    # - 渲染 Markdown 报告
    evaluator = RedTeamEvaluator()

    # ============================================================
    # 3. 批量运行所有 payload
    # ============================================================
    print("=" * 70)
    print("Agent-Sentinel Phase 4 自动化红队测试开始")
    print("=" * 70)
    print(f"当前测试用户：user_1")
    print(f"载入样本数量：{len(payloads)}")
    print("")

    results = runner.run_many(payloads)

    # ============================================================
    # 4. 对结果做统一评测
    # ============================================================
    evaluation = evaluator.evaluate(results)

    # 生成 Markdown 报告文本
    report_md = evaluator.render_markdown_report(evaluation, results)

    # ============================================================
    # 5. 保存报告文件
    # ============================================================
    ensure_reports_dir("reports")

    # 5.1 保存逐样本运行结果
    runner.save_json(results, "reports/redteam_results.json")

    # 5.2 保存汇总评测结果
    save_json(evaluation, "reports/redteam_evaluation.json")

    # 5.3 保存 Markdown 报告
    with open("reports/redteam_report.md", "w", encoding="utf-8") as f:
        f.write(report_md)

    # ============================================================
    # 6. 控制台输出简要总结
    # ============================================================
    summary = evaluation["summary"]

    print("")
    print("=" * 70)
    print("Phase 4 自动化红队测试完成")
    print("=" * 70)
    print(f"测试样本总数：{summary['total_payloads']}")
    print(f"成功运行样本数：{summary['successful_runs']}")
    print(f"运行失败样本数：{summary['failed_runs']}")
    print(f"被阻断样本数：{summary['blocked_count']}")
    print(f"执行完成样本数：{summary['completed_count']}")
    print(f"总体阻断率：{summary['block_rate']:.2%}")
    print("")

    print(f"恶意样本总数：{summary['malicious_payload_count']}")
    print(f"恶意样本阻断率：{summary['malicious_block_rate']:.2%}")
    print(f"攻击成功样本数：{summary['attack_success_count']}")
    print(f"攻击成功率：{summary['attack_success_rate']:.2%}")
    print("")

    print(f"危险 Shell 执行次数：{summary['dangerous_shell_execution_count']}")
    print(f"邮件外发执行次数：{summary['email_outbound_execution_count']}")
    print(f"HTTP 出站执行次数：{summary['http_outbound_execution_count']}")
    print(f"敏感数据外泄成功次数：{summary['exfiltration_success_count']}")
    print(f"内部探测执行次数：{summary['internal_probe_execution_count']}")
    print("")

    print("报告文件已生成：")
    print("- reports/redteam_results.json")
    print("- reports/redteam_evaluation.json")
    print("- reports/redteam_report.md")
    print("=" * 70)


if __name__ == "__main__":
    main()