"""可控屏障与本地故障注入点。

设计目标：让“提交线程 / 吊销线程”的竞争*确定性*复现，而不是靠 sleep 碰运气。

- Gate：单扇可控门。线程到达后登记并阻塞，直到编排者 release()。
- Rendezvous：基于 threading.Barrier 的 N 方集合点，用于真正同时放行的并发。
- FaultPlan：在命名故障点注入动作（模拟崩溃 / 删除已持久化回执 / 调换活动文件）。

所有同步原语都是进程内、本地、离线的；“崩溃”用 InjectedCrash 表达，
上层捕获后丢弃服务实例，再以全新对象从磁盘恢复，以模拟进程重启。
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Callable, Dict, List, Optional

from .errors import InjectedCrash


class Gate:
    """一扇门：arrive() 阻塞直到外部 open()；可选择同时记录‘已到达’事件。"""

    def __init__(self, name: str):
        self.name = name
        self._reached = threading.Event()
        self._open = threading.Event()
        self.arrived_count = 0
        self._lock = threading.Lock()

    def arrive(self, timeout: Optional[float] = 30.0) -> None:
        with self._lock:
            self.arrived_count += 1
        self._reached.set()
        if not self._open.wait(timeout=timeout):
            raise TimeoutError(f"Gate {self.name!r} 等待 open 超时")

    def wait_reached(self, timeout: Optional[float] = 10.0) -> bool:
        return self._reached.wait(timeout)

    def open(self) -> None:
        self._open.set()

    def reset(self) -> None:
        self._reached.clear()
        self._open.clear()
        with self._lock:
            self.arrived_count = 0


class Rendezvous:
    """N 方屏障：所有方到达后一起放行（封装 threading.Barrier，带超时与标签）。"""

    def __init__(self, parties: int, name: str = "rv", timeout: float = 30.0):
        self.name = name
        self.timeout = timeout
        self._barrier = threading.Barrier(parties)
        self.parties = parties

    def arrive(self) -> int:
        try:
            return self._barrier.wait(timeout=self.timeout)
        except threading.BrokenBarrierError as exc:
            raise TimeoutError(f"屏障 {self.name!r} 损坏/超时") from exc

    def reset(self) -> None:
        self._barrier.reset()

    @property
    def n_waiting(self) -> int:
        return self._barrier.n_waiting


# 故障动作：接收故障上下文，可执行任意本地副作用
FaultAction = Callable[[dict], None]


class FaultPlan:
    """按命名点武装故障。默认一次性（fire 后解除），也可 persistent。"""

    def __init__(self) -> None:
        self._actions: Dict[str, List[tuple]] = {}
        self.hits: List[str] = []
        self._lock = threading.RLock()

    def arm(self, point: str, action: FaultAction, *, persistent: bool = False) -> "FaultPlan":
        with self._lock:
            self._actions.setdefault(point, []).append((action, persistent))
        return self

    def arm_crash(self, point: str) -> "FaultPlan":
        def _crash(_ctx: dict) -> None:
            raise InjectedCrash(point)
        return self.arm(point, _crash)

    def arm_delete_path(self, point: str, path_provider: Callable[[dict], object]) -> "FaultPlan":
        """在故障点删除某个已落盘文件（例如‘持久化回执丢失’）。"""
        from pathlib import Path

        def _delete(ctx: dict) -> None:
            p = Path(path_provider(ctx))  # type: ignore[arg-type]
            try:
                p.unlink()
                ctx.setdefault("deleted_paths", []).append(str(p))
            except FileNotFoundError:
                ctx.setdefault("deleted_paths", []).append(str(p) + " (本来就不存在)")
        return self.arm(point, _delete)

    def fire(self, point: str, **ctx) -> None:
        with self._lock:
            planned = list(self._actions.get(point, ()))
            # 先摘除该点：保证一次性动作即使抛异常（如 InjectedCrash）也已解除；
            # persistent 动作在执行后按原样放回。
            self._actions.pop(point, None)
            self.hits.append(point)
        persistent_actions = []
        try:
            for action, persistent in planned:
                if persistent:
                    persistent_actions.append((action, persistent))
                action(ctx)
        finally:
            if persistent_actions:
                with self._lock:
                    self._actions.setdefault(point, []).extend(persistent_actions)

    @contextmanager
    def section(self, point: str, **ctx):
        """便于 with 语法：进入时不触发，显式 fire；此处仅提供上下文。"""
        yield
        self.fire(point, **ctx)
