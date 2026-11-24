"""哈希链决定日志（append-only JSONL）。

每条记录包含单调 seq、prev_hash 与自身 record_hash，形成轻量哈希链。
恢复时重放日志即可重建：批准记录、提交决定、吊销集合、回执状态。
日志只记录*决定与事实*，不替代实际配置摘要的重算。
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from .encoding import canonical_json, sha256_hex
from .errors import JournalTampered

GENESIS = "0" * 64


class DecisionLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()
        self._lock = threading.RLock()
        self._records: List[dict] = []
        self._last_hash = GENESIS
        self._reload_locked()

    def _reload_locked(self) -> None:
        self._records = []
        prev = GENESIS
        lines = self.path.read_text(encoding="utf-8").splitlines()
        for lineno, line in enumerate(lines, 1):
            if not line.strip():
                continue
            import json
            rec = json.loads(line)
            expected_prev = rec.get("prev_hash")
            expected_hash = rec.get("record_hash")
            # 还原追加时的 body：不含 prev_hash / record_hash
            body = {
                k: v for k, v in rec.items()
                if k not in ("record_hash", "prev_hash")
            }
            # record_hash = SHA256( 规范化(body) || 前一条哈希 )
            calc = sha256_hex(canonical_json(body) + prev.encode("ascii"))
            if expected_prev != prev:
                raise JournalTampered(f"日志第 {lineno} 行 prev_hash 断链")
            if expected_hash != calc:
                raise JournalTampered(f"日志第 {lineno} 行 record_hash 不匹配")
            self._records.append(rec)
            prev = expected_hash
        self._last_hash = prev

    def append(self, kind: str, **fields) -> dict:
        with self._lock:
            seq = len(self._records) + 1
            body = {"seq": seq, "kind": kind, **fields}
            record_hash = sha256_hex(
                canonical_json(body) + self._last_hash.encode("ascii")
            )
            rec = {**body, "prev_hash": self._last_hash, "record_hash": record_hash}
            with open(self.path, "a", encoding="utf-8") as fh:
                import json
                fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                fh.flush()
                import os
                os.fsync(fh.fileno())
            self._records.append(rec)
            self._last_hash = record_hash
            return rec

    def records(self) -> List[dict]:
        with self._lock:
            return list(self._records)

    def of_kind(self, kind: str) -> List[dict]:
        return [r for r in self.records() if r["kind"] == kind]

    def verify_chain(self) -> bool:
        """供报告调用：重新从磁盘校验整条哈希链（含 JSON 合法性/可读性）。"""
        try:
            DecisionLog(self.path)  # 重放并校验
            return True
        except (JournalTampered, ValueError, OSError):
            return False

    def __len__(self) -> int:
        return len(self._records)
