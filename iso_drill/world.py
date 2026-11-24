"""装配一个可复现的合成演练世界。

内容：
- 两个隔离工作站组；
- 每组一条 旧配置(gen1) -> 中间版本A(gen2) -> 中间版本B(gen3) -> 新配置(gen4)
  的迁移链，因此“串联两个中间版本”时共有 3 个步骤，每步一份独立双签批准；
- 两个相互独立的根控制人及其采购签发/设备安全席位；
- 信任锚文件、基线、对象库、初始活动旧配置。

本模块只生成*合成*保护配置，不含任何真实工作站数据。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from . import DRILL_GROUPS
from .approval import build_approval
from .configstore import ConfigStore, config_digest
from .encoding import write_json_atomic
from .pki import DualControl, create_separated_dual_control


# 每一代的合成规则演进（体现真实的策略代差异）
_GENERATIONS = [
    {
        "profile": "old-baseline",
        "gen": 1,
        "rules": {
            "usb_storage": "read_only",
            "macros": "warn",
            "smb_v1": "enabled_for_legacy_plc",
            "tls_min": "1.0",
            "telemetry": "offline_bundle",
        },
        "note": "旧保护配置（演练基线，含遗留 PLC 所需例外）",
    },
    {
        "profile": "intermediate-a",
        "gen": 2,
        "rules": {
            "usb_storage": "block_unless_signed",
            "macros": "block_unsigned",
            "smb_v1": "audit_only",
            "tls_min": "1.1",
            "telemetry": "offline_bundle",
        },
        "note": "中间版本 A：先把 SMBv1 降为审计、宏拦截，避免一步切换冲击产线",
    },
    {
        "profile": "intermediate-b",
        "gen": 3,
        "rules": {
            "usb_storage": "block_unless_signed",
            "macros": "block_unsigned",
            "smb_v1": "disabled",
            "tls_min": "1.2",
            "application_allowlist": "audit",
            "telemetry": "offline_bundle",
        },
        "note": "中间版本 B：关闭 SMBv1、提升 TLS、应用白名单进入审计",
    },
    {
        "profile": "new-target",
        "gen": 4,
        "rules": {
            "usb_storage": "enforce_allowlist",
            "macros": "block_all_except_trusted_publisher",
            "smb_v1": "disabled",
            "tls_min": "1.2",
            "application_allowlist": "enforce",
            "credential_guard": "enforce",
            "telemetry": "offline_bundle",
        },
        "note": "新保护配置：白名单强制 + Credential Guard",
    },
]


@dataclass
class ChainStep:
    group: str
    seq: int
    config: dict
    digest: str
    predecessor_digest: str
    approval: dict


@dataclass
class DrillWorld:
    root: Path
    dual: DualControl
    store: ConfigStore
    groups: List[str]
    # group -> 每一代 config/digest
    generations: Dict[str, List[dict]] = field(default_factory=dict)
    digests: Dict[str, List[str]] = field(default_factory=dict)
    # group -> 3 个步骤（旧->A, A->B, B->新）
    steps: Dict[str, List[ChainStep]] = field(default_factory=dict)

    def approval_ids(self, group: Optional[str] = None) -> List[str]:
        groups = [group] if group else self.groups
        ids: List[str] = []
        for g in groups:
            ids.extend(s.approval["payload"]["approval_id"] for s in self.steps[g])
        return ids


def build_world(root: Path | str, *, groups=DRILL_GROUPS, det: bool = True) -> DrillWorld:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    dual = create_separated_dual_control(det=det)
    write_json_atomic(root / "trust_anchors.json", dual.roots.to_anchor_file())

    store = ConfigStore(root / "cfg")

    world = DrillWorld(root=root, dual=dual, store=store, groups=list(groups))
    baselines: Dict[str, str] = {}

    for gi, group in enumerate(groups):
        gens: List[dict] = []
        digests: List[str] = []
        for idx, gspec in enumerate(_GENERATIONS):
            cfg = _make_generation_config(group, gspec, gi, idx)
            digest = store.write_object(cfg)
            gens.append(cfg)
            digests.append(digest)
        world.generations[group] = gens
        world.digests[group] = digests

        # 初始活动配置 = 旧配置（第 0 代）
        store.activate(group, digests[0])
        baselines[group] = digests[0]

        # 三个迁移步骤，每步独立双签批准，绑定前驱/目标摘要
        steps: List[ChainStep] = []
        for seq in range(1, 4):
            target_cfg = gens[seq]
            target_digest = digests[seq]
            predecessor_digest = digests[seq - 1]
            approval = build_approval(
                step_id=f"{group}-step-{seq}",
                seq=seq,
                config_id=target_cfg["config_id"],
                target_digest=target_digest,
                predecessor_digest=predecessor_digest,
                target_group=group,
                policy_gen=target_cfg["policy_gen"],
                procurement=dual.procurement,
                safety=dual.safety,
                statement=(
                    f"批准 {group} 由策略代 {seq} 迁移到策略代 {seq + 1} "
                    f"({_GENERATIONS[seq]['profile']})，该步骤独立可复核"
                ),
            )
            steps.append(ChainStep(
                group=group, seq=seq, config=target_cfg, digest=target_digest,
                predecessor_digest=predecessor_digest, approval=approval,
            ))
        world.steps[group] = steps

    store.save_baselines(baselines)
    return world


def _make_generation_config(group: str, gspec: dict, group_index: int, gen_index: int) -> dict:
    from .configstore import make_config
    # 编号体现组与代；同一条链上编号不同（代际版本号），另有专门的“同号异摘要”演练
    return make_config(
        config_id=f"CFG-{group.upper().replace('-', '')}-G{gspec['gen']}",
        policy_gen=gspec["gen"],
        group=group,
        profile=gspec["profile"],
        rules=dict(gspec["rules"]),
        note=gspec["note"] + f"（合成；组序号 {group_index}）",
    )
