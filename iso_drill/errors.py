"""统一的异常层次，便于测试对具体违规情形断言。"""
from __future__ import annotations


class DrillError(Exception):
    """所有演练工具错误的基类。"""


class SignatureInvalid(DrillError):
    """签名或证书验证失败。"""


class SameRootControllerError(DrillError):
    """同一根控制人试图占据采购签发与设备安全两个席位。"""


class TrustAnchorError(DrillError):
    """证书无法链接到受信任的根控制人锚点。"""


class ApprovalInvalid(DrillError):
    """批准书内容、绑定或签章无效。"""


class BindingMismatch(ApprovalInvalid):
    """签名绑定字段（摘要/组/策略代/前驱）与实际不符。"""


class SameNumberDifferentDigest(BindingMismatch):
    """同号异摘要：同一配置编号出现与批准绑定不一致的内容摘要。"""


class RevokedError(ApprovalInvalid):
    """批准书、席位或签署密钥已被吊销。"""


class LegalConfigProtected(DrillError):
    """试图删除仍合法/仍被证据链引用的配置。"""


class InjectedCrash(DrillError):
    """故障注入：模拟进程在指定故障点被杀死（内存态全部丢弃）。"""

    def __init__(self, point: str):
        super().__init__(f"[故障注入] 模拟进程在故障点崩溃: {point}")
        self.point = point


class UnprovenActiveConfig(DrillError):
    """恢复后，当前活动配置无法由落盘配置 + 决定日志证明。"""


class JournalTampered(DrillError):
    """决定日志哈希链校验失败。"""


class ConcurrencyViolation(DrillError):
    """并发编排出现非预期结果。"""


class ChainConflict(DrillError):
    """提交时当前活动摘要已不是批准绑定的前驱（并发更新/分叉）。"""
