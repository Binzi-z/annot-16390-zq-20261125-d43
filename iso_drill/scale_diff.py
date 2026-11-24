"""60000 条模拟配置记录：受影响组增量比对 vs 全量比对，并精确报告各阶段实际比对数。

计数口径（避免“扫描数”冒充“比对数”）：
- group_root_comparisons：组级聚合摘要两两比较的次数；
- record_comparisons：仅当同一 record_id 在两侧都存在、真正比较 content_hash 的次数；
- membership_checks：成员关系判定次数（新增/删除），单独列示，不计入摘要比对。

增量法两阶段：
  阶段1 比较所有组的聚合根（G 次），定位变化组；
  阶段2 只对变化（受影响）组内的记录逐条比对。
全量法：对全部 60000 个 record_id 逐条比对。
最后断言两种方法得到的变更集合完全一致。
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import GROUP_BENCH_01, GROUP_BENCH_02

TOTAL_RECORDS = 60_000
SCALE_GROUPS = [GROUP_BENCH_01, GROUP_BENCH_02] + [f"grp-site-{i:02d}" for i in range(2, 20)]
# 20 个组，60000/20 = 3000 条/组；前两组即两个受影响的隔离演练组
PER_GROUP = TOTAL_RECORDS // len(SCALE_GROUPS)
AFFECTED_GROUPS = (GROUP_BENCH_01, GROUP_BENCH_02)


def _record_hash(record_id: int, group: str, version: int, salt: int = 0) -> str:
    h = hashlib.sha256()
    h.update(f"{record_id}|{group}|v{version}|s{salt}".encode("utf-8"))
    return h.hexdigest()


def generate_records(total: int = TOTAL_RECORDS, *, mutate: bool = False) -> List[dict]:
    """确定性生成 total 条合成配置记录。

    记录按块均分到 20 个组。mutate=True 时只在两个受影响组内提升一部分
    记录版本（每组至多 120 条，小组则整组变更），组外零变更，以便检验
    “受影响组增量”确实与全量等价，同时保证两个受影响组都能被根比对发现。
    """
    records: List[dict] = []
    gcount = len(SCALE_GROUPS)
    per_group = total // gcount

    mutate_ids: Set[int] = set()
    if mutate and per_group > 0:
        n_mut = min(120, per_group)
        step = max(1, per_group // n_mut)
        for g in AFFECTED_GROUPS:
            gidx = SCALE_GROUPS.index(g)
            base = gidx * per_group
            picked = 0
            k = 0
            while picked < n_mut and k < per_group * 2:
                off = (k * step) % per_group
                gid = base + off
                if gid not in mutate_ids:
                    mutate_ids.add(gid)
                    picked += 1
                k += 1

    for i in range(total):
        gidx = min(i // max(1, per_group), gcount - 1) if per_group else 0
        group = SCALE_GROUPS[gidx]
        version = 2 if (mutate and i in mutate_ids) else 1
        records.append({
            "record_id": f"REC-{i:06d}",
            "seq": i,
            "group": group,
            "policy_gen": version,
            "content_hash": _record_hash(i, group, version),
        })
    return records


@dataclass
class CompareStats:
    group_root_comparisons: int = 0
    record_comparisons: int = 0
    membership_checks: int = 0
    records_indexed: int = 0
    elapsed_ms: float = 0.0
    stages: List[dict] = field(default_factory=list)

    def stage(self, name: str, comparisons: int, **extra) -> None:
        self.stages.append({"stage": name, "actual_comparisons": comparisons, **extra})


def index_by_id(records: List[dict]) -> Dict[str, dict]:
    return {r["record_id"]: r for r in records}


def group_aggregate_roots(records: List[dict]) -> Dict[str, str]:
    """计算每组聚合根：组内所有 content_hash 排序后再哈希。"""
    buckets: Dict[str, List[str]] = {}
    for r in records:
        buckets.setdefault(r["group"], []).append(r["content_hash"])
    roots: Dict[str, str] = {}
    for g, hashes in buckets.items():
        h = hashlib.sha256()
        for x in sorted(hashes):
            h.update(x.encode("ascii"))
        roots[g] = h.hexdigest()
    return roots


def _diff_common(
    old_idx: Dict[str, dict],
    new_idx: Dict[str, dict],
    ids: List[str],
    stats: CompareStats,
) -> Dict[str, Tuple[Optional[str], Optional[str]]]:
    changes: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
    for rid in ids:
        old = old_idx.get(rid)
        new = new_idx.get(rid)
        stats.membership_checks += 1
        if old is not None and new is not None:
            stats.record_comparisons += 1  # 真正的一次摘要比对
            if old["content_hash"] != new["content_hash"]:
                changes[rid] = (old["content_hash"], new["content_hash"])
        elif old is None and new is not None:
            changes[rid] = (None, new["content_hash"])  # added
        elif old is not None and new is None:
            changes[rid] = (old["content_hash"], None)  # removed
    return changes


def full_compare(old_records: List[dict], new_records: List[dict]) -> Tuple[dict, CompareStats]:
    stats = CompareStats(records_indexed=len(new_records))
    t0 = time.perf_counter()
    old_idx = index_by_id(old_records)
    new_idx = index_by_id(new_records)
    all_ids = sorted(set(old_idx) | set(new_idx))
    stats.stage("全量-索引并集", 0, candidate_ids=len(all_ids))
    changes = _diff_common(old_idx, new_idx, all_ids, stats)
    stats.stage("全量-逐条摘要比对", stats.record_comparisons, changed=len(changes))
    stats.elapsed_ms = (time.perf_counter() - t0) * 1000
    return changes, stats


def incremental_affected_compare(
    old_records: List[dict],
    new_records: List[dict],
    *,
    declared_affected: Optional[Tuple[str, ...]] = AFFECTED_GROUPS,
) -> Tuple[dict, CompareStats, Dict[str, object]]:
    stats = CompareStats(records_indexed=len(new_records))
    t0 = time.perf_counter()

    old_roots = group_aggregate_roots(old_records)
    new_roots = group_aggregate_roots(new_records)

    # 阶段1：组聚合根比对（每组实际比较 1 次）
    groups = sorted(set(old_roots) | set(new_roots))
    changed_groups: Set[str] = set()
    for g in groups:
        stats.group_root_comparisons += 1
        if old_roots.get(g) != new_roots.get(g):
            changed_groups.add(g)
    stats.stage(
        "增量-阶段1 组聚合根比对",
        stats.group_root_comparisons,
        groups_checked=len(groups),
        changed_groups=sorted(changed_groups),
    )

    # 声明的受影响组应恰好等于根比对发现的变化组（交叉验证）
    declared_set = set(declared_affected or ())
    root_detection_matches_declared = (changed_groups == declared_set)

    # 阶段2：只对变化组内的记录逐条比对
    old_idx = index_by_id(old_records)
    new_idx = index_by_id(new_records)
    ids_in_changed: List[str] = []
    records_per_changed_group: Dict[str, int] = {}
    for g in sorted(changed_groups):
        ids = [r["record_id"] for r in new_records if r["group"] == g]
        # 也纳入旧侧该组、新侧可能删除的 id
        old_ids = [r["record_id"] for r in old_records if r["group"] == g]
        records_per_changed_group[g] = len(set(ids) | set(old_ids))
        ids_in_changed.extend(sorted(set(ids) | set(old_ids)))
    before = stats.record_comparisons
    changes = _diff_common(old_idx, new_idx, sorted(set(ids_in_changed)), stats)
    stage2_comparisons = stats.record_comparisons - before
    stats.stage(
        "增量-阶段2 受影响组内逐条比对",
        stage2_comparisons,
        records_per_group=records_per_changed_group,
        changed=len(changes),
    )
    stats.elapsed_ms = (time.perf_counter() - t0) * 1000
    meta = {
        "changed_groups": sorted(changed_groups),
        "declared_affected": sorted(declared_set),
        "root_detection_matches_declared": root_detection_matches_declared,
        "groups_total": len(groups),
    }
    return changes, stats, meta


def run_scale_benchmark(total: int = TOTAL_RECORDS) -> dict:
    """生成 60000 条基线与变更后快照，跑两种比对并输出可序列化报告。"""
    baseline = generate_records(total, mutate=False)
    updated = generate_records(total, mutate=True)

    full_changes, full_stats = full_compare(baseline, updated)
    inc_changes, inc_stats, meta = incremental_affected_compare(baseline, updated)

    equivalent = full_changes == inc_changes
    gcount = len(SCALE_GROUPS)
    per_group_dynamic = total // gcount
    affected_record_total = per_group_dynamic * len(AFFECTED_GROUPS)
    report = {
        "total_simulated_records": total,
        "group_count": gcount,
        "records_per_group": per_group_dynamic,
        "affected_groups": list(AFFECTED_GROUPS),
        "affected_group_record_total": affected_record_total,
        "actual_changed_records": len(full_changes),
        "equivalent_change_sets": equivalent,
        "incremental": {
            "group_root_comparisons_stage1": inc_stats.group_root_comparisons,
            "record_comparisons_stage2": next(
                s["actual_comparisons"] for s in inc_stats.stages
                if s["stage"].startswith("增量-阶段2")
            ),
            "total_record_hash_comparisons": inc_stats.record_comparisons,
            "stages": inc_stats.stages,
            "elapsed_ms": round(inc_stats.elapsed_ms, 2),
            **meta,
        },
        "full": {
            "record_comparisons": full_stats.record_comparisons,
            "membership_checks": full_stats.membership_checks,
            "stages": full_stats.stages,
            "elapsed_ms": round(full_stats.elapsed_ms, 2),
        },
        "comparison_reduction": {
            "full_record_comparisons": full_stats.record_comparisons,
            "incremental_record_comparisons": inc_stats.record_comparisons,
            "saved_record_comparisons": full_stats.record_comparisons - inc_stats.record_comparisons,
            "ratio_full_over_incremental": round(
                full_stats.record_comparisons / max(1, inc_stats.record_comparisons), 2
            ),
            "note": (
                "增量法另有 "
                f"{inc_stats.group_root_comparisons} 次组聚合根比对；"
                "记录级比对从 60000 降到受影响组内数量"
            ),
        },
    }
    # 健全性断言（被测试与 CLI 共用）
    if not equivalent:
        raise AssertionError("增量与全量变更集合不一致")
    if full_stats.record_comparisons != total:
        raise AssertionError("全量比对次数应为记录总数")
    if inc_stats.record_comparisons != affected_record_total:
        raise AssertionError("增量记录比对次数应为受影响组记录总数")
    return report
