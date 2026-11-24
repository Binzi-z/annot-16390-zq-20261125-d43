"""合成保护配置 + 内容寻址对象库 + 活动配置原子切换 + 合法配置保留保护。

磁盘布局（root 之下）：
    objects/<digest>.json   不可变内容寻址对象（所有出现过的版本都留档）
    active/<group>.json     每组*实际生效*的配置文件，切换 = os.replace 原子改名
    baselines.json          两组的受信基线摘要（演练起点）

关键不变量：
1. 摘要直接对落盘字节计算，批准绑定的是这个摘要；
2. 更新只新增 object 并原子替换 active，绝不删除旧 object；
3. 受保护（基线/已批准/被证据引用）的 object 若被并发清理误删，
   delete_digest 会抛 LegalConfigProtected，文件保留。
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Dict, Iterable, Optional, Set, Tuple

from .encoding import (
    atomic_write_bytes,
    digest_file,
    read_json,
    render_pretty,
    sha256_hex,
    write_json_atomic,
)
from .errors import LegalConfigProtected


def make_config(
    *,
    config_id: str,
    policy_gen: int,
    group: str,
    profile: str,
    rules: Dict[str, object],
    note: str = "",
) -> dict:
    """构造一份确定性的*合成*保护配置（无任何真实系统数据）。"""
    return {
        "schema": "iso-drill/protection-config/v1",
        "synthetic": True,
        "config_id": config_id,          # 配置编号（可能被“同号异摘要”复用）
        "policy_gen": policy_gen,        # 策略代
        "target_group": group,           # 目标设备组
        "profile": profile,              # old / intermediate / new
        "protection": {
            "mode": "enforce",
            "rules": dict(sorted(rules.items())),
        },
        "note": note,
    }


def config_bytes(cfg: dict) -> bytes:
    return render_pretty(cfg)


def config_digest(cfg: dict) -> str:
    return sha256_hex(config_bytes(cfg))


class ConfigStore:
    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.objects_dir = self.root / "objects"
        self.active_dir = self.root / "active"
        self.objects_dir.mkdir(parents=True, exist_ok=True)
        self.active_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._protected: Set[str] = set()

    # ---------- 内容寻址对象 ----------
    def object_path(self, digest: str) -> Path:
        return self.objects_dir / f"{digest}.json"

    def write_object(self, cfg: dict) -> str:
        """写入不可变对象；返回摘要。相同内容幂等。"""
        data = config_bytes(cfg)
        digest = sha256_hex(data)
        path = self.object_path(digest)
        with self._lock:
            if not path.exists():
                atomic_write_bytes(path, data)
            else:
                # 同摘要必须同字节；若落盘内容哈希不符说明对象被破坏
                actual = digest_file(path)
                if actual != digest:
                    raise LegalConfigProtected(
                        f"内容寻址对象损坏: {path.name} 内容摘要 {actual} != {digest}"
                    )
        return digest

    def has_object(self, digest: str) -> bool:
        return self.object_path(digest).exists()

    def read_object(self, digest: str) -> Tuple[dict, bytes]:
        path = self.object_path(digest)
        data = path.read_bytes()
        actual = sha256_hex(data)
        if actual != digest:
            raise LegalConfigProtected(
                f"对象摘要校验失败: 文件名 {digest[:12]} 实际 {actual[:12]}"
            )
        return read_json(path), data

    def object_digest_on_disk(self, digest: str) -> Optional[str]:
        path = self.object_path(digest)
        return digest_file(path) if path.exists() else None

    # ---------- 活动配置文件（真正被切换的文件） ----------
    def active_path(self, group: str) -> Path:
        _validate_group(group)
        return self.active_dir / f"{group}.json"

    def activate(self, group: str, digest: str) -> Path:
        """把指定对象的*确切字节*原子切换为该组活动配置。"""
        _cfg, data = self.read_object(digest)
        path = self.active_path(group)
        atomic_write_bytes(path, data)  # os.replace：配置文件切换点
        return path

    def active_digest(self, group: str) -> Optional[str]:
        path = self.active_path(group)
        if not path.exists():
            return None
        return digest_file(path)  # 始终重算实际落盘摘要

    def read_active(self, group: str) -> dict:
        return read_json(self.active_path(group))

    # ---------- 合法配置保留保护 ----------
    def protect(self, digest: str) -> None:
        with self._lock:
            self._protected.add(digest)

    def protect_many(self, digests: Iterable[str]) -> None:
        with self._lock:
            self._protected.update(digests)

    def is_protected(self, digest: str) -> bool:
        with self._lock:
            return digest in self._protected

    def protected_digests(self) -> Set[str]:
        with self._lock:
            return set(self._protected)

    def delete_digest(self, digest: str) -> bool:
        """模拟并发清理/GC。受保护（合法）配置一律拒绝删除。

        返回 True 表示确实删除了未受保护对象；受保护时抛 LegalConfigProtected。
        """
        with self._lock:
            if digest in self._protected:
                raise LegalConfigProtected(
                    f"摘要 {digest[:12]} 是合法/被引用配置，禁止并发删除"
                )
            path = self.object_path(digest)
            if path.exists():
                path.unlink()
                return True
            return False

    def force_delete_for_fault(self, digest: str) -> None:
        """仅用于制造‘回执/文件丢失’故障：绕过保留保护的底层删除。

        演练中只允许用它删除*回执文件*或明确注入故障，不用于合法配置。
        """
        path = self.object_path(digest)
        if path.exists():
            path.unlink()

    # ---------- 基线 ----------
    def save_baselines(self, mapping: Dict[str, str]) -> None:
        write_json_atomic(self.root / "baselines.json", {"baselines": dict(sorted(mapping.items()))})
        self.protect_many(mapping.values())

    def load_baselines(self) -> Dict[str, str]:
        doc = read_json(self.root / "baselines.json")
        return dict(doc["baselines"])


def _validate_group(group: str) -> None:
    if not group or not all(c.isalnum() or c in "-_" for c in group):
        raise ValueError(f"非法设备组标识（防路径穿越）: {group!r}")
