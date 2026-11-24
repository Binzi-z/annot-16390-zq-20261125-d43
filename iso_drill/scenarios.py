"""确定性演练场景：吊销抢先、切换后回执丢失、同号异摘要、并发保留。

每个场景使用独立的全新目录，返回可 JSON 序列化的结果（含逐项检查）。
CLI 与 unittest 共用这些场景，避免“演示一套、测试另一套”。
"""
from __future__ import annotations

import shutil
import threading
import traceback
from pathlib import Path
from typing import Callable, Optional

from . import DRILL_GROUPS, GROUP_BENCH_01, GROUP_BENCH_02
from .approval import bind_actual_config, build_approval, evaluate_approval
from .configstore import config_bytes, make_config
from .errors import (
    InjectedCrash,
    LegalConfigProtected,
    RevokedError,
    SameNumberDifferentDigest,
    ChainConflict,
)
from .faults import FaultPlan, Gate, Rendezvous
from .recovery import Recovery
from .service import DrillService
from .world import build_world


class Outcome:
    def __init__(self, key: str, title: str):
        self.key = key
        self.title = title
        self.checks = []
        self.data = {}

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.checks.append({"name": name, "passed": bool(passed), "detail": detail})
        return bool(passed)

    def finalize(self) -> dict:
        ok = all(c["passed"] for c in self.checks)
        return {
            "key": self.key,
            "title": self.title,
            "ok": ok,
            "checks": self.checks,
            "data": self.data,
        }


def fresh_dir(path: Path) -> Path:
    path = Path(path)
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def start_thread(fn: Callable, *args, **kwargs):
    box: dict = {}

    def _wrap():
        try:
            box["value"] = fn(*args, **kwargs)
        except BaseException as exc:  # 捕获并回传，断言在主线程做
            box["error"] = exc

    t = threading.Thread(target=_wrap, daemon=True)
    t.start()
    return t, box


def _expect(exc_types, fn: Callable, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_types as exc:
        return exc
    except Exception as exc:  # noqa: BLE001 - 演练需要分类任何异常
        return AssertionError(f"期望 {exc_types}，实际抛出 {type(exc).__name__}: {exc}")
    return AssertionError(f"期望抛出 {exc_types}，但未抛出")


# ---------------------------------------------------------------------------
# 场景 0：完整双链 + 两中间版本，每步独立批准，正常恢复得到最短 3 步证据
# ---------------------------------------------------------------------------
def scenario_happy_chain(workdir: Path) -> dict:
    out = Outcome("happy_chain", "两组迁移全链：两个中间版本、每步独立双签批准")
    world = build_world(fresh_dir(workdir))
    svc = DrillService(workdir)

    committed = []
    for g in world.groups:
        for step in world.steps[g]:
            committed.append(svc.submit(step.approval))

    out.check("两组各 3 步（旧→A→B→新）共 6 次提交成功",
              len(committed) == 6 and all(r["status"] == "committed" for r in committed),
              f"committed={len(committed)}")

    # 从磁盘逐一独立复核批准书（不使用内存对象）
    disk_reports = []
    for ap in sorted(svc.approvals_dir.glob("*.json")):
        from .encoding import read_json
        apr = read_json(ap)
        rep = evaluate_approval(apr, svc.roots)
        disk_reports.append(rep)
    out.check("磁盘上 6 份批准书均可独立复核为有效（双签/异根/绑定）",
              len(disk_reports) == 6 and all(r["valid"] for r in disk_reports),
              f"valid {sum(r['valid'] for r in disk_reports)}/6")

    rec = Recovery(workdir)
    reports = rec.recover_all(list(world.groups))
    all_ok = True
    summaries = {}
    for g in world.groups:
        rep = reports[g]
        expect_digest = world.digests[g][3]
        ok = (
            rep["verdict"] == "proven"
            and rep["shortest_step_count"] == 3
            and rep["active_digest_recomputed_from_disk"] == expect_digest
            and not rep["missing_original_receipts"]
            and rep["all_legal_configs_preserved"]
        )
        all_ok &= ok
        summaries[g] = {
            "shortest_step_count": rep["shortest_step_count"],
            "verdict": rep["verdict"],
            "active_short": rep["active_digest_recomputed_from_disk"][:12],
            "evidence_file": rep["evidence_file"],
        }
    out.check("恢复重算：两组均为 3 步最短证据、回执齐全、旧配置全保留", all_ok)
    out.data["recovery"] = summaries
    return out.finalize()


# ---------------------------------------------------------------------------
# 场景 1：吊销抢先 —— 提交/吊销两个真实线程 + 可控门确定性排序
# ---------------------------------------------------------------------------
def scenario_revoke_preempt(workdir: Path) -> dict:
    out = Outcome("revoke_preempt", "吊销抢先：吊销线程在提交线性化前完成")
    g = GROUP_BENCH_01
    world = build_world(fresh_dir(workdir), groups=(g,))
    svc = DrillService(workdir)
    approval = world.steps[g][0].approval
    aid = approval["payload"]["approval_id"]

    gate = Gate("before_commit_linearization")
    t_sub, box_sub = start_thread(svc.submit, approval, pre_commit_gate=gate)

    reached = gate.wait_reached(timeout=45)
    out.check("提交线程完成签章复核并到达提交前可控门", reached)

    # 提交线程在门外阻塞（未持 commit_lock），吊销线程得以完整抢先
    t_rev, box_rev = start_thread(
        svc.revoke, aid, "演练：采购签发终端失联，预防性紧急吊销"
    )
    t_rev.join(timeout=30)
    out.check("吊销线程已完成 REVOKED 决定",
              not t_rev.is_alive() and "error" not in box_rev,
              str(box_rev.get("error", "")))

    gate.open()
    t_sub.join(timeout=30)
    err = box_sub.get("error")
    out.check("门放行后提交被吊销状态拦截（RevokedError）",
              isinstance(err, RevokedError),
              f"实际={type(err).__name__ if err else '无异常'}")

    revokes = svc.log.of_kind("REVOKED")
    rejects = svc.log.of_kind("SUBMIT_REJECTED")
    out.check("决定日志顺序：REVOKED 先于 SUBMIT_REJECTED",
              len(revokes) == 1 and len(rejects) == 1
              and revokes[-1]["seq"] < rejects[-1]["seq"],
              f"revoke_seq={revokes[-1]['seq'] if revokes else None}, "
              f"reject_seq={rejects[-1]['seq'] if rejects else None}")
    out.check("不存在任何 COMMITTED 记录", not svc.log.of_kind("COMMITTED"))
    out.check("活动配置仍是旧基线（吊销的配置未生效）",
              svc.store.active_digest(g) == world.digests[g][0])
    out.check("未生成该批准的提交回执", not svc.receipt_path(aid).exists())

    rec = Recovery(workdir)
    rep = rec.shortest_evidence(g)
    out.check("恢复：活动=基线，最短证据 0 步且结论 proven",
              rep["verdict"] == "proven" and rep["shortest_step_count"] == 0)
    out.check("恢复：被吊销批准形成的证据边被拒绝并注明原因",
              any(e["approval_id"] == aid and "吊销" in e.get("reason", "")
                  for e in rep["rejected_edges"]))
    out.data["approval_id"] = aid
    return out.finalize()


# ---------------------------------------------------------------------------
# 场景 2a：配置文件已切换，但在写持久化回执前“进程崩溃”
# ---------------------------------------------------------------------------
def scenario_receipt_crash_before_write(workdir: Path) -> dict:
    out = Outcome("receipt_crash_before_write", "切换后/回执前崩溃：从落盘与日志重建证据")
    g = GROUP_BENCH_01
    world = build_world(fresh_dir(workdir), groups=(g,))
    svc = DrillService(workdir)
    steps = world.steps[g]

    svc.submit(steps[0].approval)
    svc.submit(steps[1].approval)
    svc.faults.arm_crash("after_switch")  # 仅对第 3 步一次性武装

    err = _expect(InjectedCrash, svc.submit, steps[2].approval)
    aid3 = steps[2].approval["payload"]["approval_id"]
    out.check("第 3 步在 after_switch 故障点抛出 InjectedCrash",
              isinstance(err, InjectedCrash), str(err))
    out.check("配置文件切换已落盘：活动摘要=新配置摘要",
              svc.store.active_digest(g) == world.digests[g][3])
    out.check("第 3 步回执尚不存在", not svc.receipt_path(aid3).exists())
    committed_aids = {r["approval_id"] for r in svc.log.of_kind("COMMITTED")}
    out.check("第 3 步没有 COMMITTED 日志（前两步有）",
              aid3 not in committed_aids and len(committed_aids) == 2)

    # 模拟进程重启：丢弃 svc 内存态，仅以磁盘构造恢复器
    del svc
    rec = Recovery(workdir)
    rep = rec.shortest_evidence(g)
    out.check("恢复结论 proven 且最短证据=3 步",
              rep["verdict"] == "proven" and rep["shortest_step_count"] == 3)
    out.check("仅第 3 步原始回执缺失，前两步回执在盘",
              rep["missing_original_receipts"] == [aid3],
              f"missing={[x[:16] for x in rep['missing_original_receipts']]}")
    out.check("未伪造回执，证据报告注明由落盘+日志重算",
              "未伪造" in rep["receipt_note"])
    out.check("四代合法配置全部仍在盘且摘要正确",
              rep["all_legal_configs_preserved"])
    out.data["evidence_file"] = rep["evidence_file"]
    return out.finalize()


# ---------------------------------------------------------------------------
# 场景 2b：回执已持久化后被本地故障“丢失”（最字面意义的持久化回执丢失）
# ---------------------------------------------------------------------------
def scenario_receipt_deleted_after_persist(workdir: Path) -> dict:
    out = Outcome("receipt_lost_after_persist", "持久化回执写盘后丢失：恢复重算最短证据")
    g = GROUP_BENCH_02
    world = build_world(fresh_dir(workdir), groups=(g,))
    svc = DrillService(workdir)
    steps = world.steps[g]

    svc.submit(steps[0].approval)
    svc.submit(steps[1].approval)
    svc.faults.arm_delete_path(
        "after_receipt_persist", lambda ctx: ctx["receipt_path"]
    )
    res3 = svc.submit(steps[2].approval)
    aid3 = steps[2].approval["payload"]["approval_id"]

    out.check("提交返回但回执已不在盘（receipt_persisted=False）",
              res3["status"] == "committed" and res3["receipt_persisted"] is False
              and not svc.receipt_path(aid3).exists())
    committed = [r for r in svc.log.of_kind("COMMITTED") if r["approval_id"] == aid3]
    out.check("COMMITTED 日志如实记录 receipt_persisted=false",
              len(committed) == 1 and committed[0]["receipt_persisted"] is False)

    rec = Recovery(workdir)
    rep = rec.shortest_evidence(g)
    out.check("恢复仍得到 3 步 proven 最短证据",
              rep["verdict"] == "proven" and rep["shortest_step_count"] == 3)
    out.check("丢失回执被显式列出且不影响证据成立（日志+落盘可重算）",
              rep["missing_original_receipts"] == [aid3])
    return out.finalize()


# ---------------------------------------------------------------------------
# 场景 3a：同号异摘要 —— 纯绑定层
# ---------------------------------------------------------------------------
def scenario_same_number_binding(workdir: Path) -> dict:
    out = Outcome("same_number_binding", "同号异摘要：绑定层拒绝用 A 批准复核 B 内容")
    g = GROUP_BENCH_01
    world = build_world(fresh_dir(workdir), groups=(g,))
    step1 = world.steps[g][0]
    approval = step1.approval

    # 正向：同摘要真实配置通过绑定
    good_cfg = bind_actual_config(approval, config_bytes(step1.config))
    out.check("同摘要真实配置通过绑定", good_cfg["config_id"] == step1.config["config_id"])

    evil = dict(step1.config)
    evil["protection"] = {
        "mode": "disabled",  # 篡改：关闭防护
        "rules": {"usb_storage": "allow_all", "smb_v1": "enabled"},
    }
    evil["note"] = "同号异摘要的伪造配置"
    evil_digest = world.store.write_object(evil)
    out.check("伪造配置与批准绑定摘要不同",
              evil_digest != approval["payload"]["target_digest"])

    exc = _expect(SameNumberDifferentDigest,
                  bind_actual_config, approval, config_bytes(evil))
    out.check("抛出 SameNumberDifferentDigest",
              isinstance(exc, SameNumberDifferentDigest), str(exc))
    return out.finalize()


# ---------------------------------------------------------------------------
# 场景 3b：提交切换后被越界调包成同号异摘要文件 —— 提交前重读取拦截，不写假回执
# ---------------------------------------------------------------------------
def scenario_out_of_band_swap(workdir: Path) -> dict:
    out = Outcome("out_of_band_swap", "故障点越界调包：切换后同号异摘要顶替被拦截")
    g = GROUP_BENCH_01
    world = build_world(fresh_dir(workdir), groups=(g,))
    step1 = world.steps[g][0]
    aid = step1.approval["payload"]["approval_id"]

    evil = dict(step1.config)
    evil["protection"] = {"mode": "disabled", "rules": {"usb_storage": "allow_all"}}
    evil_digest = world.store.write_object(evil)

    faults = FaultPlan().arm(
        "after_switch",
        lambda ctx: world.store.activate(g, evil_digest),  # 模拟越界/陈旧写入调包
    )
    svc = DrillService(workdir, faults=faults)
    exc = _expect(SameNumberDifferentDigest, svc.submit, step1.approval)
    out.check("提交重读取发现同号异摘要并拒绝",
              isinstance(exc, SameNumberDifferentDigest), str(exc))
    out.check("未写出与批准不符的回执", not svc.receipt_path(aid).exists())
    out.check("记录了 SUBMIT_CONFLICT", bool(svc.log.of_kind("SUBMIT_CONFLICT")))

    # 运维回滚到受信旧基线后，恢复结论重新 proven
    svc.store.activate(g, world.digests[g][0])
    rec = Recovery(workdir)
    rep = rec.shortest_evidence(g)
    out.check("回滚基线后恢复为 0 步 proven，旧合法配置未被删除",
              rep["verdict"] == "proven" and rep["shortest_step_count"] == 0
              and world.store.has_object(world.digests[g][0]))
    return out.finalize()


# ---------------------------------------------------------------------------
# 场景 3c：两个真实提交线程 + Barrier，同号异摘要分叉竞争
# ---------------------------------------------------------------------------
def scenario_duplicate_digest_race(workdir: Path) -> dict:
    out = Outcome("duplicate_digest_race", "同号异摘要并发分叉：Barrier 同时放行，仅一个线性化")
    g = GROUP_BENCH_01
    world = build_world(fresh_dir(workdir), groups=(g,))
    baseline = world.digests[g][0]
    seats = world.dual

    cfg_a = make_config(
        config_id="CFG-DUP-007", policy_gen=9, group=g, profile="fork-a",
        rules={"usb_storage": "block", "branch": "A"},
    )
    cfg_b = make_config(
        config_id="CFG-DUP-007", policy_gen=9, group=g, profile="fork-b",
        rules={"usb_storage": "allow_all", "branch": "B"},  # 同号、同代、异摘要
    )
    d_a = world.store.write_object(cfg_a)
    d_b = world.store.write_object(cfg_b)
    out.check("A/B 同 config_id 但摘要不同", d_a != d_b)

    apr_a = build_approval(
        step_id="dup-a", seq=901, config_id="CFG-DUP-007", target_digest=d_a,
        predecessor_digest=baseline, target_group=g, policy_gen=9,
        procurement=seats.procurement, safety=seats.safety,
    )
    apr_b = build_approval(
        step_id="dup-b", seq=902, config_id="CFG-DUP-007", target_digest=d_b,
        predecessor_digest=baseline, target_group=g, policy_gen=9,
        procurement=seats.procurement, safety=seats.safety,
    )

    svc = DrillService(workdir)
    rv = Rendezvous(2, "dup-fork")
    ta, box_a = start_thread(svc.submit, apr_a, rendezvous=rv)
    tb, box_b = start_thread(svc.submit, apr_b, rendezvous=rv)
    ta.join(timeout=60)
    tb.join(timeout=60)

    boxes = [box_a, box_b]
    committed = [b["value"] for b in boxes if "value" in b]
    conflicts = [b["error"] for b in boxes if isinstance(b.get("error"), ChainConflict)]
    out.check("恰好 1 个分叉提交成功", len(committed) == 1,
              f"committed={len(committed)}")
    out.check("另 1 个因前驱 CAS 冲突被拒（ChainConflict）", len(conflicts) == 1,
              f"conflicts={len(conflicts)}; "
              f"other_err={[type(b.get('error')).__name__ for b in boxes if 'error' in b]}")

    if committed:
        winner = committed[0]["digest"]
        out.check("活动摘要与获胜回执一致", svc.store.active_digest(g) == winner)
        rec = Recovery(workdir)
        rep = rec.shortest_evidence(g)
        out.check("恢复得到到获胜摘要的 1 步 proven 证据",
                  rep["verdict"] == "proven" and rep["shortest_step_count"] == 1
                  and rep["active_digest_recomputed_from_disk"] == winner)
    out.check("两个同号异摘要对象与基线对象都被保留（未被并发更新误删）",
              world.store.has_object(d_a) and world.store.has_object(d_b)
              and world.store.has_object(baseline))
    out.data["digests"] = {"A": d_a[:12], "B": d_b[:12]}
    return out.finalize()


# ---------------------------------------------------------------------------
# 场景 4：高并发“更新 + 激进 GC”下，旧合法配置绝不被误删
# ---------------------------------------------------------------------------
def scenario_concurrent_preservation(workdir: Path) -> dict:
    out = Outcome("concurrent_preservation", "并发更新/清理压力下旧合法配置保留")
    world = build_world(fresh_dir(workdir))
    store = world.store

    legal = set()
    for g in world.groups:
        legal.update(world.digests[g])
    store.protect_many(legal)

    blocked = {"n": 0}
    deleted_tmp = {"n": 0}
    lock = threading.Lock()
    errors = []

    def worker(tid: int):
        try:
            for i in range(15):
                cfg = make_config(
                    config_id=f"CFG-TMP-{tid}-{i}", policy_gen=100 + i,
                    group=f"grp-t{tid}", profile="tmp",
                    rules={"k": f"{tid}-{i}-unique"},
                )
                dtmp = store.write_object(cfg)
                # 并发地尝试删除*每一个*受保护的合法旧配置
                for digest in list(legal):
                    try:
                        store.delete_digest(digest)
                        errors.append("受保护配置竟被删除: " + digest[:12])
                    except LegalConfigProtected:
                        with lock:
                            blocked["n"] += 1
                if store.delete_digest(dtmp):
                    with lock:
                        deleted_tmp["n"] += 1
        except BaseException as exc:  # noqa: BLE001
            errors.append(f"worker {tid} 异常: {type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    out.check("8 个工作线程全部结束且无意外错误", not errors, "; ".join(errors[:3]))
    out.check("对合法配置的删除全部被保留保护拦截", blocked["n"] >= 8 * 15 * len(legal),
              f"blocked={blocked['n']}, legal={len(legal)}")
    out.check("未受保护的临时对象可正常 GC", deleted_tmp["n"] == 8 * 15,
              f"deleted={deleted_tmp['n']}")

    all_present = all(
        store.has_object(d) and store.object_digest_on_disk(d) == d for d in legal
    )
    out.check("压力结束后全部旧合法配置仍在盘且摘要正确", all_present)

    exc = _expect(LegalConfigProtected, store.delete_digest, world.digests[GROUP_BENCH_01][0])
    out.check("主线程再次尝试删除基线仍被拒绝", isinstance(exc, LegalConfigProtected))
    out.data["blocked_deletes"] = blocked["n"]
    return out.finalize()


ALL_SCENARIOS = [
    scenario_happy_chain,
    scenario_revoke_preempt,
    scenario_receipt_crash_before_write,
    scenario_receipt_deleted_after_persist,
    scenario_same_number_binding,
    scenario_out_of_band_swap,
    scenario_duplicate_digest_race,
    scenario_concurrent_preservation,
]


def run_all(base_dir: Path) -> dict:
    base_dir = Path(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for fn in ALL_SCENARIOS:
        key = fn.__name__
        sub = base_dir / key
        try:
            results.append(fn(sub))
        except Exception as exc:  # noqa: BLE001 - 顶层兜底，保证报告完整
            results.append({
                "key": key,
                "title": key,
                "ok": False,
                "checks": [],
                "data": {},
                "fatal": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
            })
    total_checks = sum(len(r.get("checks", [])) for r in results)
    passed_checks = sum(
        sum(1 for c in r.get("checks", []) if c["passed"]) for r in results
    )
    return {
        "all_ok": all(r.get("ok") for r in results),
        "scenario_count": len(results),
        "total_checks": total_checks,
        "passed_checks": passed_checks,
        "results": results,
    }
