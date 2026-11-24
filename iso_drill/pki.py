"""合成 PKI：根控制人(Root Controller) -> 角色席位证书。

职责分离约束（题面硬性要求）：
    采购签发者 与 设备安全员 必须由*两个不同的根控制人*分别授权；
    同一个根控制人不能同时占据/签出这两个席位。

信任模型（离线演练）：
    每个根控制人有一对 Ed25519 根密钥，其公钥作为带外信任锚登记在
    TrustedRoots。根密钥给席位公钥签发证书。验签时只信任 TrustedRoots
    中按 root_id 锚定的根公钥，不轻信证书内自带的 root_pub。
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Optional

from . import ed25519
from .encoding import canonical_json, sha256_hex
from .errors import SameRootControllerError, SignatureInvalid, TrustAnchorError

CERT_VERSION = 1


def _new_seed(deterministic_label: Optional[str] = None) -> bytes:
    if deterministic_label is not None:
        # 仅用于可复现的合成演练身份；真实系统必须使用 CSPRNG/HSM。
        return sha256_hex(b"iso-drill-seed-v1::" + deterministic_label.encode("utf-8"))[
            :32
        ].encode("ascii")
    return secrets.token_bytes(32)


@dataclass
class RootController:
    root_id: str
    label_zh: str
    seed: bytes = field(repr=False)
    public_key: bytes = field(init=False)

    def __post_init__(self) -> None:
        self.public_key = ed25519.public_key(self.seed)

    @classmethod
    def create(cls, root_id: str, label_zh: str, det_label: Optional[str] = None):
        return cls(root_id=root_id, label_zh=label_zh, seed=_new_seed(det_label or root_id))

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(self.seed, message)


@dataclass
class Seat:
    seat_id: str
    role: str
    root_id: str
    seed: bytes = field(repr=False)
    public_key: bytes = field(init=False)
    cert: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.public_key = ed25519.public_key(self.seed)

    @classmethod
    def create(cls, seat_id: str, role: str, root: RootController,
               det_label: Optional[str] = None) -> "Seat":
        seat = cls(
            seat_id=seat_id,
            role=role,
            root_id=root.root_id,
            seed=_new_seed(det_label or ("seat::" + seat_id)),
        )
        seat.cert = issue_certificate(root, seat)
        return seat

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(self.seed, message)


def issue_certificate(root: RootController, seat: Seat) -> dict:
    """根控制人为席位公钥签发角色证书。"""
    tbs = {
        "cert_version": CERT_VERSION,
        "root_id": root.root_id,
        "seat_id": seat.seat_id,
        "role": seat.role,
        "seat_pub": seat.public_key.hex(),
    }
    root_sig = root.sign(canonical_json(tbs)).hex()
    return {**tbs, "root_sig": root_sig}


class TrustedRoots:
    """离线信任锚：root_id -> 根公钥。"""

    def __init__(self) -> None:
        self._anchors: Dict[str, bytes] = {}

    def add(self, root: RootController) -> "TrustedRoots":
        self._anchors[root.root_id] = root.public_key
        return self

    def public_key_for(self, root_id: str) -> bytes:
        try:
            return self._anchors[root_id]
        except KeyError as exc:
            raise TrustAnchorError(f"未知/不受信任的根控制人: {root_id}") from exc

    def has(self, root_id: str) -> bool:
        return root_id in self._anchors

    def to_anchor_file(self) -> dict:
        return {
            "schema": "iso-drill/trust-anchors/v1",
            "roots": [
                {"root_id": rid, "root_pub": pub.hex()}
                for rid, pub in sorted(self._anchors.items())
            ],
        }

    @classmethod
    def from_anchor_file(cls, doc: dict) -> "TrustedRoots":
        tr = cls()
        for item in doc.get("roots", []):
            tr._anchors[item["root_id"]] = bytes.fromhex(item["root_pub"])
        return tr


@lru_cache(maxsize=None)
def _cert_signature_valid(anchor_pub_hex: str, tbs_canonical: bytes, root_sig_hex: str) -> bool:
    """纯函数式证书签名校验缓存：相同锚点公钥+TBS+签名结果一致。"""
    try:
        return ed25519.verify(
            bytes.fromhex(anchor_pub_hex),
            tbs_canonical,
            bytes.fromhex(root_sig_hex),
        )
    except Exception:
        return False


def verify_certificate(cert: dict, roots: TrustedRoots) -> dict:
    """用信任锚中的根公钥验证席位证书，返回 TBS 字段。"""
    if not isinstance(cert, dict) or cert.get("cert_version") != CERT_VERSION:
        raise SignatureInvalid("证书结构/版本不受支持")
    root_id = cert.get("root_id")
    anchor_pub = roots.public_key_for(root_id)  # 可能抛 TrustAnchorError

    tbs = {
        "cert_version": cert["cert_version"],
        "root_id": cert["root_id"],
        "seat_id": cert["seat_id"],
        "role": cert["role"],
        "seat_pub": cert["seat_pub"],
    }
    try:
        root_sig_hex = cert["root_sig"]
        # 校验字段为合法十六进制
        bytes.fromhex(root_sig_hex)
        bytes.fromhex(tbs["seat_pub"])
    except (KeyError, ValueError, TypeError) as exc:
        raise SignatureInvalid("证书字段缺失或不是合法十六进制") from exc

    if not _cert_signature_valid(anchor_pub.hex(), canonical_json(tbs), root_sig_hex):
        raise SignatureInvalid(f"席位证书无法由根控制人 {root_id} 验签")
    return tbs


def assert_distinct_roots(proc_cert: dict, safety_cert: dict) -> None:
    """核心职责分离规则：同一根控制人不得占两席。"""
    rp = proc_cert.get("root_id")
    rs = safety_cert.get("root_id")
    if not rp or not rs:
        raise SameRootControllerError("两份席位证书缺少 root_id")
    if rp == rs:
        raise SameRootControllerError(
            f"采购签发者与设备安全员同属一个根控制人 {rp}，违反两席独立原则"
        )


@dataclass
class DualControl:
    """一对*合规*的独立席位及其信任锚。"""

    roots: TrustedRoots
    procurement_root: RootController
    safety_root: RootController
    procurement: Seat
    safety: Seat

    def as_roots(self) -> TrustedRoots:
        return self.roots


def create_separated_dual_control(det: bool = True) -> DualControl:
    """创建由两个不同根控制人分别授权的两个席位（合规配置）。"""
    suffix = "fixed" if det else None
    proc_root = RootController.create(
        "ROOT-PROC-01", "采购签发根控制人",
        det_label=(suffix + ":proc-root") if det else None,
    )
    safety_root = RootController.create(
        "ROOT-SAFE-02", "设备安全根控制人",
        det_label=(suffix + ":safe-root") if det else None,
    )
    procurement = Seat.create(
        "SEAT-PROC-1", "procurement_issuer", proc_root,
        det_label=(suffix + ":proc-seat") if det else None,
    )
    safety = Seat.create(
        "SEAT-SAFE-1", "device_safety_officer", safety_root,
        det_label=(suffix + ":safe-seat") if det else None,
    )
    roots = TrustedRoots().add(proc_root).add(safety_root)
    return DualControl(roots, proc_root, safety_root, procurement, safety)


def create_same_root_pair(det: bool = True):
    """反例：同一个根控制人同时签发两个角色席位（必须被拒绝）。"""
    root = RootController.create(
        "ROOT-MONO-9", "单一垄断根控制人",
        det_label="mono-root" if det else None,
    )
    proc = Seat.create(
        "SEAT-MONO-P", "procurement_issuer", root,
        det_label="mono-proc" if det else None,
    )
    safety = Seat.create(
        "SEAT-MONO-S", "device_safety_officer", root,
        det_label="mono-safe" if det else None,
    )
    roots = TrustedRoots().add(root)
    return roots, proc, safety
