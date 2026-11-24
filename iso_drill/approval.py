"""双签迁移批准书：签名绑定（实际配置摘要、目标设备组、策略代、前驱摘要）。

每份批准书由*两个不同根控制人*下辖的席位独立签署：
    - 采购签发者 procurement_issuer
    - 设备安全员 device_safety_officer

任何第三方仅凭磁盘上的批准书 + 信任锚 + 实际配置字节即可离线复核，
不依赖进程内存。evaluate_approval 收集逐项检查结论，供“独立可复核”展示。
"""
from __future__ import annotations

import json
from typing import Callable, Dict, List, Optional

from . import ROLE_SAFETY, ROLE_PROCUREMENT
from . import ed25519
from .encoding import canonical_json, sha256_hex
from .errors import (
    BindingMismatch,
    RevokedError,
    SameNumberDifferentDigest,
    SameRootControllerError,
)
from .pki import Seat, TrustedRoots, assert_distinct_roots, verify_certificate

APPROVAL_SCHEMA = "iso-drill/migration-approval/v1"

# 吊销判定回调：入参 (approval_id, [seat_id...])，返回吊销原因字符串或 None
RevocationCheck = Callable[[str, List[str]], Optional[str]]


def derive_approval_id(payload: dict) -> str:
    return "APR-" + sha256_hex(canonical_json(payload))[:16]


def build_approval(
    *,
    step_id: str,
    seq: int,
    config_id: str,
    target_digest: str,
    predecessor_digest: str,
    target_group: str,
    policy_gen: int,
    procurement: Seat,
    safety: Seat,
    statement: str = "",
) -> dict:
    """构造并由两席分别签名。构造期即强制根控制人分离。"""
    if procurement.role != ROLE_PROCUREMENT:
        raise ValueError("procurement 席位角色不是采购签发者")
    if safety.role != ROLE_SAFETY:
        raise ValueError("safety 席位角色不是设备安全员")
    # 构造期硬约束：同一根控制人不能占两席
    assert_distinct_roots(procurement.cert, safety.cert)

    core = {
        "schema": APPROVAL_SCHEMA,
        "step_id": step_id,
        "seq": seq,
        "config_id": config_id,
        "target_digest": target_digest,
        "predecessor_digest": predecessor_digest,
        "target_group": target_group,
        "policy_gen": policy_gen,
        "statement": statement,
    }
    # approval_id 由绑定核心确定性派生，随后与核心一起被两席签名。
    payload = dict(core)
    payload["approval_id"] = "APR-" + sha256_hex(canonical_json(core))[:16]

    signing_bytes = canonical_json(payload)
    approval = {
        "payload": payload,
        "procurement": {
            "seat_id": procurement.seat_id,
            "cert": procurement.cert,
            "sig": procurement.sign(signing_bytes).hex(),
        },
        "safety": {
            "seat_id": safety.seat_id,
            "cert": safety.cert,
            "sig": safety.sign(signing_bytes).hex(),
        },
    }
    return approval


def _check_one_signer(
    block: dict, expected_role: str, roots: TrustedRoots, signing_bytes: bytes
) -> Dict[str, object]:
    """验证一个签署方的证书、角色与签名，返回结论明细。"""
    cert = block.get("cert", {})
    tbs = verify_certificate(cert, roots)  # 失败会抛 SignatureInvalid/TrustAnchorError
    if tbs["role"] != expected_role:
        raise BindingMismatch(
            f"席位角色不符：期望 {expected_role}，实际 {tbs['role']}"
        )
    if block.get("seat_id") != tbs["seat_id"]:
        raise BindingMismatch("签名块 seat_id 与证书不一致")
    seat_pub = bytes.fromhex(tbs["seat_pub"])
    sig = bytes.fromhex(block.get("sig", ""))
    if not ed25519.verify(seat_pub, signing_bytes, sig):
        raise BindingMismatch(f"{expected_role} 签名验证失败")
    return {
        "seat_id": tbs["seat_id"],
        "role": tbs["role"],
        "root_id": tbs["root_id"],
        "signature_valid": True,
        "cert_valid": True,
    }


def evaluate_approval(
    approval: dict,
    roots: TrustedRoots,
    *,
    revocation_check: Optional[RevocationCheck] = None,
) -> dict:
    """纯复核：签章、证书锚定、根分离、吊销状态。不触碰实际配置字节。

    返回结构化报告；任何失败都体现在 valid=False/errors，不向调用方抛，
    以便把“每一步独立可复核”的结论完整呈现。
    """
    checks: List[dict] = []
    errors: List[str] = []
    signers: List[dict] = []
    payload = approval.get("payload", {}) if isinstance(approval, dict) else {}
    signing_bytes = canonical_json(payload)
    approval_id = payload.get("approval_id", "<unknown>")

    # 1) 两席签章 + 证书
    for key, role, zh in (
        ("procurement", ROLE_PROCUREMENT, "采购签发者"),
        ("safety", ROLE_SAFETY, "设备安全员"),
    ):
        try:
            info = _check_one_signer(approval[key], role, roots, signing_bytes)
            info["role_zh"] = zh
            signers.append(info)
            checks.append({"check": f"{zh}独立签署/验签", "ok": True})
        except Exception as exc:  # 复核需要收集而非中断
            errors.append(f"{zh}: {type(exc).__name__}: {exc}")
            checks.append({"check": f"{zh}独立签署/验签", "ok": False, "error": str(exc)})

    # 2) 同一根控制人不得占两席
    try:
        assert_distinct_roots(
            approval["procurement"]["cert"], approval["safety"]["cert"]
        )
        checks.append({"check": "两席根控制人相互独立", "ok": True})
    except SameRootControllerError as exc:
        errors.append(str(exc))
        checks.append({"check": "两席根控制人相互独立", "ok": False, "error": str(exc)})
    except Exception as exc:
        errors.append(f"根分离检查无法完成: {exc}")
        checks.append({"check": "两席根控制人相互独立", "ok": False, "error": str(exc)})

    # 3) approval_id 与绑定内容一致
    try:
        bound_id = payload.get("approval_id")
        core = {k: payload[k] for k in (
            "schema", "step_id", "seq", "config_id", "target_digest",
            "predecessor_digest", "target_group", "policy_gen", "statement")}
        expect_id = "APR-" + sha256_hex(canonical_json(core))[:16]
        if bound_id != expect_id:
            errors.append("approval_id 与绑定内容派生值不一致")
            checks.append({"check": "批准编号完整性", "ok": False})
        else:
            checks.append({"check": "批准编号完整性", "ok": True})
    except KeyError as exc:
        errors.append(f"payload 缺少绑定字段: {exc}")

    # 4) 吊销
    if revocation_check is not None and not errors:
        seat_ids = [str(s.get("seat_id")) for s in signers]
        reason = revocation_check(str(approval_id), seat_ids)
        if reason:
            errors.append(f"已吊销: {reason}")
            checks.append({"check": "未被吊销", "ok": False, "error": reason})
        else:
            checks.append({"check": "未被吊销", "ok": True})

    return {
        "valid": not errors,
        "approval_id": approval_id,
        "step_id": payload.get("step_id"),
        "seq": payload.get("seq"),
        "config_id": payload.get("config_id"),
        "target_digest": payload.get("target_digest"),
        "predecessor_digest": payload.get("predecessor_digest"),
        "target_group": payload.get("target_group"),
        "policy_gen": payload.get("policy_gen"),
        "signers": signers,
        "checks": checks,
        "errors": errors,
    }


def verify_or_raise(
    approval: dict,
    roots: TrustedRoots,
    *,
    revocation_check: Optional[RevocationCheck] = None,
) -> dict:
    report = evaluate_approval(approval, roots, revocation_check=revocation_check)
    if not report["valid"]:
        raise BindingMismatch("; ".join(report["errors"]))
    return report


def bind_actual_config(approval: dict, actual_bytes: bytes) -> dict:
    """把批准书与*实际落盘配置字节*比对，强制摘要/组/策略代/编号一致。

    若配置编号相同但摘要不同，判定为“同号异摘要”并抛专门异常。
    返回实际配置对象。
    """
    payload = approval["payload"]
    actual_digest = sha256_hex(actual_bytes)
    try:
        actual_cfg = json.loads(actual_bytes.decode("utf-8"))
    except Exception as exc:
        raise BindingMismatch(f"实际配置不是合法 JSON: {exc}") from exc

    bound_digest = payload["target_digest"]
    if actual_digest != bound_digest:
        same_no = actual_cfg.get("config_id") == payload.get("config_id")
        if same_no:
            raise SameNumberDifferentDigest(
                f"配置编号 {payload.get('config_id')} 同号异摘要："
                f"批准绑定 {bound_digest[:12]}，实际落盘 {actual_digest[:12]}"
            )
        raise BindingMismatch(
            f"配置摘要不符：批准 {bound_digest[:12]}，实际 {actual_digest[:12]}"
        )

    # 摘要已一致 => 内容必然一致；下面是更明确的字段级防御检查
    if actual_cfg.get("target_group") != payload["target_group"]:
        raise BindingMismatch("实际配置目标设备组与批准绑定不一致")
    if actual_cfg.get("policy_gen") != payload["policy_gen"]:
        raise BindingMismatch("实际配置策略代与批准绑定不一致")
    if actual_cfg.get("config_id") != payload["config_id"]:
        raise BindingMismatch("实际配置编号与批准绑定不一致")
    return actual_cfg
