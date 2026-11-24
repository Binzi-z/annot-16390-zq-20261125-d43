"""故障恢复：只信*实际落盘配置*与*哈希链决定日志*，重算最短证据。

恢复流程（全部基于磁盘，新建对象，不使用崩溃前内存态）：
1. 重新打开并校验 decisions.jsonl 哈希链；重放吊销集合。
2. 直接哈希 active/<group>.json 得到“当前实际摘要”。
3. 逐一独立复核 approvals/*.json（签章/根分离/吊销），并要求：
   - 目标摘要对应的 objects/<digest>.json 真实存在且重算摘要一致；
   - 决定日志中存在该 approval_id 的记录（进入过决定流）。
   满足后才形成 predecessor_digest -> target_digest 的证据边。
4. 从受信基线出发 BFS，求到当前实际摘要的*最短*批准链。
5. 标注哪些原始回执已丢失（不伪造原回执），另写重算证据报告。
6. 用重算出的合法集合重新武装保留保护，阻止并发 GC 删除旧合法配置。
"""
from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .approval import evaluate_approval
from .configstore import ConfigStore
from .encoding import read_json, short, write_json_atomic
from .errors import UnprovenActiveConfig
from .journal import DecisionLog
from .pki import TrustedRoots


class Recovery:
    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.store = ConfigStore(self.root / "cfg")
        self.log = DecisionLog(self.root / "decisions.jsonl")  # 构造即校验哈希链
        anchor_doc = read_json(self.root / "trust_anchors.json")
        self.roots = TrustedRoots.from_anchor_file(anchor_doc)
        self.baselines: Dict[str, str] = self.store.load_baselines()
        self.approvals_dir = self.root / "approvals"
        self.receipts_dir = self.root / "receipts"
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        state = self._revoked_state()
        self.revoked_approvals: Set[str] = state["approvals"]
        self.revoked_seats: Set[str] = state["seats"]
        self.records_by_approval: Dict[str, List[dict]] = {}
        for rec in self.log.records():
            aid = rec.get("approval_id") or rec.get("target_approval")
            if aid:
                self.records_by_approval.setdefault(aid, []).append(rec)

    def _revoked_state(self) -> Dict[str, Set[str]]:
        approvals: Set[str] = set()
        seats: Set[str] = set()
        for rec in self.log.of_kind("REVOKED"):
            if rec.get("target_approval"):
                approvals.add(rec["target_approval"])
            if rec.get("seat_id"):
                seats.add(rec["seat_id"])
        return {"approvals": approvals, "seats": seats}

    def revocation_check(self, approval_id: str, seat_ids: List[str]) -> Optional[str]:
        """符合 approval.evaluate_approval 契约的回调：(aid, sids)->原因|None。"""
        if approval_id in self.revoked_approvals:
            return "批准已吊销"
        if any(s in self.revoked_seats for s in seat_ids):
            return "席位已吊销"
        return None

    # ---------- 构造证据图 ----------
    def build_edges(self, group: str) -> Tuple[Dict[str, List[dict]], List[dict], List[dict]]:
        adjacency: Dict[str, List[dict]] = {}
        admissible: List[dict] = []
        rejected: List[dict] = []

        for apath in sorted(self.approvals_dir.glob("*.json")):
            approval = read_json(apath)
            payload = approval.get("payload", {})
            aid = payload.get("approval_id", apath.stem)
            if payload.get("target_group") != group:
                continue

            review = evaluate_approval(
                approval, self.roots,
                revocation_check=self.revocation_check,
            )
            to = payload.get("target_digest")
            frm = payload.get("predecessor_digest")

            reason: Optional[str] = None
            if not review["valid"]:
                reason = "复核未过: " + "; ".join(review["errors"])
            elif not to or not self.store.has_object(to):
                reason = "目标配置对象不在实际落盘对象库"
            elif self.store.object_digest_on_disk(to) != to:
                reason = "目标对象重算摘要与文件名/绑定不符（损坏或篡改）"
            elif aid not in self.records_by_approval:
                reason = "决定日志中没有该批准的任何记录"

            edge_info = {
                "approval_id": aid,
                "step_id": payload.get("step_id"),
                "seq": payload.get("seq"),
                "config_id": payload.get("config_id"),
                "policy_gen": payload.get("policy_gen"),
                "from": frm,
                "to": to,
                "receipt_on_disk": (self.receipts_dir / f"{aid}.receipt.json").exists(),
                "log_kinds": sorted({r["kind"] for r in self.records_by_approval.get(aid, [])}),
                "root_ids": [s.get("root_id") for s in review.get("signers", [])],
            }
            if reason:
                edge_info["reason"] = reason
                rejected.append(edge_info)
                continue

            admissible.append(edge_info)
            adjacency.setdefault(frm, []).append(edge_info)

        # 确定性边序：按 seq / approval_id
        for edges in adjacency.values():
            edges.sort(key=lambda e: (e.get("seq") is None, e.get("seq", 0), e["approval_id"]))
        return adjacency, admissible, rejected

    # ---------- BFS 最短证据 ----------
    def shortest_evidence(self, group: str) -> dict:
        if group not in self.baselines:
            raise UnprovenActiveConfig(f"缺少组 {group} 的受信基线")
        baseline = self.baselines[group]
        active = self.store.active_digest(group)
        if active is None:
            raise UnprovenActiveConfig(f"组 {group} 没有实际活动配置文件")

        adjacency, admissible, rejected = self.build_edges(group)

        # 重新武装合法配置保留：基线 + 所有可采边端点
        legal: Set[str] = {baseline, active}
        for e in admissible:
            legal.add(e["to"])
            if e.get("from"):
                legal.add(e["from"])
        self.store.protect_many(legal)

        path_edges: List[dict] = []
        found = baseline == active
        if not found:
            queue = deque([baseline])
            prev_node: Dict[str, Optional[str]] = {baseline: None}
            prev_edge: Dict[str, Optional[dict]] = {baseline: None}
            while queue and not found:
                node = queue.popleft()
                for edge in adjacency.get(node, []):
                    nxt = edge["to"]
                    if nxt in prev_node:
                        continue
                    prev_node[nxt] = node
                    prev_edge[nxt] = edge
                    if nxt == active:
                        found = True
                        break
                    queue.append(nxt)
            if found:
                cur = active
                while cur != baseline:
                    edge = prev_edge[cur]
                    assert edge is not None
                    path_edges.append(edge)
                    cur = prev_node[cur]  # type: ignore[assignment]
                path_edges.reverse()

        missing_receipts = [e["approval_id"] for e in path_edges if not e["receipt_on_disk"]]

        # 旧合法配置保留审计：基线上的每一代对象都必须仍在盘上
        preservation = []
        for digest in sorted(legal):
            preservation.append({
                "digest": digest,
                "exists_on_disk": self.store.has_object(digest),
                "digest_recomputed_matches": self.store.object_digest_on_disk(digest) == digest,
                "protected": self.store.is_protected(digest),
            })
        all_preserved = all(x["exists_on_disk"] and x["digest_recomputed_matches"] for x in preservation)

        verdict = "proven" if found and all_preserved else "unproven"
        report = {
            "schema": "iso-drill/shortest-evidence/v1",
            "group": group,
            "verdict": verdict,
            "baseline_digest": baseline,
            "active_digest_recomputed_from_disk": active,
            "reachable": found,
            "shortest_step_count": len(path_edges),
            "shortest_path": [
                {
                    "order": i + 1,
                    "step_id": e["step_id"],
                    "seq": e["seq"],
                    "approval_id": e["approval_id"],
                    "config_id": e["config_id"],
                    "policy_gen": e["policy_gen"],
                    "from_short": short(e["from"]),
                    "to_short": short(e["to"]),
                    "to_digest": e["to"],
                    "independent_review": "valid (双签+异根+未吊销+日志可查+落盘摘要一致)",
                    "receipt_on_disk": e["receipt_on_disk"],
                    "log_kinds": e["log_kinds"],
                    "root_ids": e["root_ids"],
                }
                for i, e in enumerate(path_edges)
            ],
            "missing_original_receipts": missing_receipts,
            "receipt_note": (
                "原始回执丢失，未伪造；本报告依据实际落盘配置与哈希链决定日志重算生成"
                if missing_receipts else "路径上各步原始回执均在盘"
            ),
            "admissible_edge_count": len(admissible),
            "rejected_edges": rejected,
            "legal_config_preservation": preservation,
            "all_legal_configs_preserved": all_preserved,
            "decision_log_records": len(self.log.records()),
            "decision_log_chain_valid": self.log.verify_chain(),
        }

        out = self.evidence_dir / f"{group}.shortest.json"
        write_json_atomic(out, report)
        report["evidence_file"] = str(out)
        if not found:
            raise UnprovenActiveConfig(
                f"组 {group} 无法从基线 {short(baseline)} 证明活动摘要 {short(active)}；"
                f"被拒边 {len(rejected)} 条"
            )
        return report

    def recover_all(self, groups: List[str]) -> Dict[str, dict]:
        reports: Dict[str, dict] = {}
        for g in groups:
            reports[g] = self.shortest_evidence(g)
        return reports
