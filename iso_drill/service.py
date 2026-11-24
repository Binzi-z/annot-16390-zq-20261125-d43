"""迁移服务：提交线程与吊销线程共用的离线事务核心。

并发正确性要点：
- 同一把 commit_lock 串行化“吊销决定”和“提交线性化段”，因此吊销与提交
  存在确定的先后顺序；编排层用 Gate/Barrier 决定谁先到达。
- 配置切换(os.replace)之后、写回执之前/之后都设有本地故障点。
- 写回执前*重新从磁盘读取活动配置并比对摘要*，防止“切换后被同号异摘要
  配置顶替”却写出与批准不符的回执。
- 吊销状态唯一来源是哈希链决定日志中的 REVOKED 记录。
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict, List, Optional

from .approval import (
    bind_actual_config,
    evaluate_approval,
)
from .configstore import ConfigStore
from .encoding import atomic_write_bytes, read_json, write_json_atomic
from .errors import ApprovalInvalid, ChainConflict, RevokedError
from .faults import FaultPlan, Gate, Rendezvous
from .journal import DecisionLog
from .pki import TrustedRoots


class DrillService:
    def __init__(self, root: Path | str, *, faults: Optional[FaultPlan] = None):
        self.root = Path(root)
        (self.root / "approvals").mkdir(parents=True, exist_ok=True)
        (self.root / "receipts").mkdir(parents=True, exist_ok=True)
        self.store = ConfigStore(self.root / "cfg")
        self.log = DecisionLog(self.root / "decisions.jsonl")
        anchor_doc = read_json(self.root / "trust_anchors.json")
        self.roots = TrustedRoots.from_anchor_file(anchor_doc)
        self.faults = faults or FaultPlan()
        # 同一把锁同时保护提交线性化段与吊销决定
        self.commit_lock = threading.RLock()

    # ---------- 路径 ----------
    @property
    def approvals_dir(self) -> Path:
        return self.root / "approvals"

    @property
    def receipts_dir(self) -> Path:
        return self.root / "receipts"

    def approval_path(self, approval_id: str) -> Path:
        return self.approvals_dir / f"{approval_id}.json"

    def receipt_path(self, approval_id: str) -> Path:
        return self.receipts_dir / f"{approval_id}.receipt.json"

    # ---------- 吊销状态（唯一来源：决定日志） ----------
    def revoked_state(self) -> Dict[str, object]:
        approvals = set()
        seats = set()
        reasons: Dict[str, str] = {}
        for rec in self.log.of_kind("REVOKED"):
            if rec.get("target_approval"):
                approvals.add(rec["target_approval"])
                reasons[rec["target_approval"]] = rec.get("reason", "")
            if rec.get("seat_id"):
                seats.add(rec["seat_id"])
        return {"approvals": approvals, "seats": seats, "reasons": reasons}

    def revocation_check(self):
        """返回符合 approval.evaluate_approval 约定的回调 check(aid, sids)->reason|None。"""
        state = self.revoked_state()

        def _check(aid: str, sids: List[str]) -> Optional[str]:
            if aid in state["approvals"]:  # type: ignore[operator]
                return "该批准书已被吊销: " + str(state["reasons"].get(aid, ""))  # type: ignore[union-attr]
            bad = [s for s in sids if s in state["seats"]]  # type: ignore[operator]
            if bad:
                return f"签署席位密钥已被吊销: {bad}"
            return None

        return _check

    # ---------- 批准书登记（落盘，供独立复核） ----------
    def register_approval(self, approval: dict) -> str:
        approval_id = approval["payload"]["approval_id"]
        path = self.approval_path(approval_id)
        is_new = not path.exists()
        if is_new:
            write_json_atomic(path, approval)
            p = approval["payload"]
            self.log.append(
                "APPROVAL_REGISTERED",
                approval_id=approval_id,
                step_id=p["step_id"],
                payload_seq=p["seq"],
                config_id=p["config_id"],
                target_digest=p["target_digest"],
                predecessor_digest=p["predecessor_digest"],
                target_group=p["target_group"],
                policy_gen=p["policy_gen"],
            )
        return approval_id

    def load_approval(self, approval_id: str) -> dict:
        return read_json(self.approval_path(approval_id))

    # ---------- 吊销（由吊销线程调用） ----------
    def revoke(self, approval_id: str, reason: str, *, seat_id: Optional[str] = None) -> dict:
        with self.commit_lock:
            rec = self.log.append(
                "REVOKED",
                target_approval=approval_id,
                seat_id=seat_id,
                reason=reason,
            )
        return rec

    # ---------- 提交（由提交线程调用） ----------
    def submit(
        self,
        approval: dict,
        *,
        pre_commit_gate: Optional[Gate] = None,
        rendezvous: Optional[Rendezvous] = None,
    ) -> dict:
        p = approval["payload"]
        approval_id = p["approval_id"]
        group = p["target_group"]
        target_digest = p["target_digest"]

        # 1) 结构/签章/根分离先验（此时尚不检查吊销，吊销抢先由线性化段裁决）
        pre = evaluate_approval(approval, self.roots)
        if not pre["valid"]:
            raise ApprovalInvalid("批准书复核失败: " + "; ".join(pre["errors"]))

        self.register_approval(approval)
        self.log.append(
            "SUBMIT_RECEIVED",
            approval_id=approval_id,
            target_group=group,
            target_digest=target_digest,
        )

        # 2) 可控屏障：在进入线性化段*之前*等待，使吊销线程可以抢先完成。
        #    不能持锁等待，否则吊销线程无法进入同一把锁 -> 死锁。
        if pre_commit_gate is not None:
            pre_commit_gate.arrive()
        if rendezvous is not None:
            rendezvous.arrive()

        # 3) 提交线性化段
        with self.commit_lock:
            # 签章/根分离在屏障前已完整验证且批准对象不可变；线性化点只需
            # 重新裁决“是否已被吊销”，这正是与吊销线程的竞争焦点。
            signer_ids = [s.get("seat_id", "") for s in pre.get("signers", [])]
            revoke_reason = self.revocation_check()(approval_id, signer_ids)
            if revoke_reason:
                msg = "批准书/席位已被吊销: " + revoke_reason
                self.log.append(
                    "SUBMIT_REJECTED", approval_id=approval_id, reason=msg
                )
                raise RevokedError(msg)

            if not self.store.has_object(target_digest):
                msg = "批准目标配置对象不在离线对象库中"
                self.log.append("SUBMIT_REJECTED", approval_id=approval_id, reason=msg)
                raise ApprovalInvalid(msg)

            # 前驱 CAS：活动摘要必须仍是本批准绑定的 predecessor_digest。
            # 这把“同号异摘要”的并发分叉串行化——只有一个后继能线性化成功。
            current_digest = self.store.active_digest(group)
            if current_digest != p["predecessor_digest"]:
                msg = (
                    f"前驱冲突：批准要求 {str(p['predecessor_digest'])[:12]}，"
                    f"实际活动为 {str(current_digest)[:12]}"
                )
                self.log.append(
                    "SUBMIT_CONFLICT", approval_id=approval_id,
                    group=group, current_digest=current_digest, reason=msg,
                )
                raise ChainConflict(msg)

            # 3a) 真正切换活动配置文件（原子 os.replace）
            active_path = self.store.activate(group, target_digest)

            # 故障点：切换之后、回执之前（可注入“进程崩溃”）
            self.faults.fire(
                "after_switch",
                approval_id=approval_id, group=group,
                active_path=str(active_path), receipt_path=str(self.receipt_path(approval_id)),
            )

            # 3b) 提交前从*实际落盘*重新读取并绑定，拦截同号异摘要顶替
            actual_bytes = active_path.read_bytes()
            try:
                bind_actual_config(approval, actual_bytes)
            except Exception as exc:
                self.log.append(
                    "SUBMIT_CONFLICT",
                    approval_id=approval_id,
                    group=group,
                    actual_digest=self.store.active_digest(group),
                    error=f"{type(exc).__name__}: {exc}",
                )
                raise

            # 3c) 持久化回执
            receipt = {
                "schema": "iso-drill/commit-receipt/v1",
                "approval_id": approval_id,
                "target_group": group,
                "config_id": p["config_id"],
                "policy_gen": p["policy_gen"],
                "target_digest": target_digest,
                "active_digest_after_switch": self.store.active_digest(group),
            }
            rpath = self.receipt_path(approval_id)
            atomic_write_bytes(rpath, json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"))

            # 故障点：回执已写盘之后（可注入“删除回执”或崩溃）
            self.faults.fire(
                "after_receipt_persist",
                approval_id=approval_id, receipt_path=str(rpath),
            )
            receipt_on_disk = rpath.exists()

            self.log.append(
                "COMMITTED",
                approval_id=approval_id,
                target_group=group,
                target_digest=target_digest,
                receipt_persisted=receipt_on_disk,
            )
            self.store.protect(target_digest)
            return {
                "status": "committed",
                "approval_id": approval_id,
                "group": group,
                "digest": target_digest,
                "receipt_persisted": receipt_on_disk,
            }
