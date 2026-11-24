"""规范化序列化、摘要与原子落盘工具（仅标准库）。"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

HEX = str


def canonical_json(value: Any) -> bytes:
    """签名用规范化字节：键排序、紧凑分隔、不转义非 ASCII。"""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def render_pretty(value: Any) -> bytes:
    """落盘配置的固定布局（确定性），文件摘要直接对这些字节计算。"""
    text = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)
    return (text + "\n").encode("utf-8")


def sha256_hex(data: bytes) -> HEX:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: os.PathLike | str) -> HEX:
    """读取*实际落盘字节*并计算摘要——恢复/复核只信任它。"""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_obj(value: Any) -> HEX:
    return sha256_hex(render_pretty(value))


def atomic_write_bytes(path: os.PathLike | str, data: bytes) -> None:
    """同目录临时文件 + flush/fsync + os.replace，保证 Windows 上原子切换。

    os.replace 在 Windows 上可原子替换已存在文件。临时文件用 mkstemp 唯一名，
    多线程并发也不会踩到同一个临时名。
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".tmp-" + path.name + "-", dir=str(path.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def read_json(path: os.PathLike | str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json_atomic(path: os.PathLike | str, value: Any) -> None:
    atomic_write_bytes(path, render_pretty(value))


def short(digest: str, n: int = 12) -> str:
    if digest is None:
        return "<none>"
    return digest[:n]
