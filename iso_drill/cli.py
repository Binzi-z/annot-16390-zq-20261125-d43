"""命令行编排：运行全部演练场景 + 60000 条比对，落盘 JSON/Markdown 报告。

用法（原生 Windows，仅标准库）：
    py -3.12 run_drill.py
    python -m iso_drill
    python -m iso_drill --work artifacts\\run --keep

退出码：全部检查通过为 0，否则 1。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .scale_diff import run_scale_benchmark
from .scenarios import run_all


def _markdown_report(scenario_report: dict, scale_report: dict) -> str:
    lines = ["# 隔离工作站双凭据迁移演练报告", ""]
    lines.append(f"- 场景数：{scenario_report['scenario_count']}")
    lines.append(
        f"- 检查项：{scenario_report['passed_checks']}/{scenario_report['total_checks']} 通过"
    )
    lines.append(f"- 总体结论：{'✅ 全部通过' if scenario_report['all_ok'] else '❌ 存在失败'}")
    lines.append("")

    lines.append("## 一、并发 / 批准 / 恢复场景")
    for r in scenario_report["results"]:
        mark = "✅" if r.get("ok") else "❌"
        lines.append(f"\n### {mark} {r['title']} (`{r['key']}`)")
        if r.get("fatal"):
            lines.append(f"- 💥 场景抛出未预期异常：`{r['fatal']}`")
        for c in r.get("checks", []):
            cm = "✅" if c["passed"] else "❌"
            detail = f" — {c['detail']}" if c.get("detail") else ""
            lines.append(f"  - {cm} {c['name']}{detail}")

    lines.append("\n## 二、60000 条记录：受影响组增量 vs 全量")
    inc = scale_report["incremental"]
    full = scale_report["full"]
    red = scale_report["comparison_reduction"]
    lines.append(f"- 模拟记录总数：**{scale_report['total_simulated_records']}**")
    lines.append(f"- 组数 / 每组：{scale_report['group_count']} / {scale_report['records_per_group']}")
    lines.append(f"- 受影响组：{', '.join(scale_report['affected_groups'])}")
    lines.append(f"- 受影响组记录数：{scale_report['affected_group_record_total']}")
    lines.append(f"- 实际变更记录：{scale_report['actual_changed_records']}")
    lines.append(f"- 两种方法变更集完全等价：**{scale_report['equivalent_change_sets']}**")
    lines.append("")
    lines.append("| 阶段 | 实际比对数量 |")
    lines.append("|---|---:|")
    lines.append(f"| 增量·阶段1 组聚合根比对 | {inc['group_root_comparisons_stage1']} |")
    lines.append(f"| 增量·阶段2 受影响组内记录摘要比对 | {inc['record_comparisons_stage2']} |")
    lines.append(f"| 增量·记录级摘要比对合计 | {inc['total_record_hash_comparisons']} |")
    lines.append(f"| 全量·逐条记录摘要比对 | {full['record_comparisons']} |")
    lines.append("")
    lines.append(
        f"- 记录级比对从 {red['full_record_comparisons']} 降到 "
        f"{red['incremental_record_comparisons']}，少比 "
        f"{red['saved_record_comparisons']} 条，约 "
        f"{red['ratio_full_over_incremental']}× 减量。"
    )
    lines.append(f"- 增量耗时 {inc['elapsed_ms']} ms；全量耗时 {full['elapsed_ms']} ms。")
    lines.append("")
    return "\n".join(lines)


def _force_utf8_stdio() -> None:
    """原生 Windows 常见 cp936/重定向管道：尽量切到 UTF-8 且永不因打印崩。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            try:
                stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
            except Exception:
                pass


def main(argv=None) -> int:
    _force_utf8_stdio()
    parser = argparse.ArgumentParser(description="隔离工作站双凭据迁移离线演练工具")
    parser.add_argument("--work", default="artifacts/run", help="演练工作/报告目录")
    parser.add_argument("--scale", type=int, default=60000, help="模拟配置记录数")
    args = parser.parse_args(argv)

    work = Path(args.work)
    scenarios_dir = work / "scenarios"
    work.mkdir(parents=True, exist_ok=True)

    print("=" * 72)
    print("隔离工作站：旧保护配置 -> 新配置 双凭据批准 / 并发吊销 / 恢复取证 演练")
    print("仅使用 Python 标准库，全部为合成数据，离线运行")
    print("=" * 72)

    t0 = time.perf_counter()
    scenario_report = run_all(scenarios_dir)
    for r in scenario_report["results"]:
        mark = "[PASS]" if r.get("ok") else "[FAIL]"
        print(f"\n{mark} {r['title']}")
        if r.get("fatal"):
            print("   FATAL:", r["fatal"])
        for c in r.get("checks", []):
            print(f"   {'  ok ' if c['passed'] else ' FAIL'} {c['name']}"
                  + (f"  ({c['detail']})" if c.get("detail") and not c["passed"] else ""))

    print("\n" + "-" * 72)
    print(f"检查项 {scenario_report['passed_checks']}/{scenario_report['total_checks']} 通过")
    print("-" * 72)

    print("\n[scale] 生成并比对 %d 条模拟配置记录 ..." % args.scale)
    scale_report = run_scale_benchmark(args.scale)
    inc = scale_report["incremental"]
    full = scale_report["full"]
    print(f"  增量 阶段1 组聚合根比对 : {inc['group_root_comparisons_stage1']}")
    print(f"  增量 阶段2 组内记录比对 : {inc['record_comparisons_stage2']}")
    print(f"  增量 记录比对合计       : {inc['total_record_hash_comparisons']}")
    print(f"  全量 逐条记录比对       : {full['record_comparisons']}")
    print(f"  变更集等价              : {scale_report['equivalent_change_sets']}")
    print(f"  实际变更记录            : {scale_report['actual_changed_records']}")

    (work / "report.json").write_text(
        json.dumps(
            {"scenarios": scenario_report, "scale": scale_report},
            ensure_ascii=False, indent=2,
        ),
        encoding="utf-8",
    )
    md = _markdown_report(scenario_report, scale_report)
    (work / "REPORT.md").write_text(md, encoding="utf-8")

    elapsed = time.perf_counter() - t0
    print("\n报告已写入:")
    print("  ", (work / "report.json").resolve())
    print("  ", (work / "REPORT.md").resolve())
    print(f"总耗时 {elapsed:.1f}s")

    return 0 if scenario_report["all_ok"] and scale_report["equivalent_change_sets"] else 1


if __name__ == "__main__":
    sys.exit(main())
