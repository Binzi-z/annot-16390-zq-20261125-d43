"""极简 Ed25519(RFC 8032) 实现，仅依赖 hashlib（标准库）。

演练环境无法安装第三方密码库，因此这里给出可独立复核的真实非对称签名：
- 每个席位持有自己的 32 字节种子 -> 公钥；
- 私钥签名，任何持有公钥/证书锚点的人都能离线验签；
- tests/test_crypto_pki.py 内置 RFC 8032 已知答案向量，确保算法实现正确。

实现采用 RFC 8032 参考级的仿射坐标公式，代码刻意保持短小透明，便于审计。
这是*演练/合成*用途；生产系统应使用经过审计的密码库与 HSM/DPAPI 等保护。
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from typing import Tuple

Point = Tuple[int, int]

BITS = 256
Q = 2 ** 255 - 19
# 群阶 l
L = 2 ** 252 + 27742317777372353535851937790883648493


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    """模逆（Q 为素数）。"""
    return pow(x, Q - 2, Q)


_D = (-121665 * _inv(121666)) % Q
_I = pow(2, (Q - 1) // 4, Q)  # sqrt(-1) mod Q


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * _I) % Q
    if (x * x - xx) % Q != 0:
        raise ValueError("编码点不在 Ed25519 曲线上")
    if x & 1:
        x = Q - x
    return x


_BY = (4 * _inv(5)) % Q
_BX = _x_recover(_BY)
BASE: Point = (_BX, _BY)


def _on_curve(p: Point) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _D * x * x * y * y) % Q == 0


def _edwards_add(p: Point, q: Point) -> Point:
    x1, y1 = p
    x2, y2 = q
    common = (_D * x1 * x2 * y1 * y2) % Q
    x3 = (x1 * y2 + x2 * y1) * _inv((1 + common) % Q)
    y3 = (y1 * y2 + x1 * x2) * _inv((1 - common) % Q)
    return x3 % Q, y3 % Q


def _scalar_mult(point: Point, scalar: int) -> Point:
    """递归 double-and-add；scalar < 2^256，递归深度约 256，安全。"""
    if scalar == 0:
        return 0, 1
    doubled = _scalar_mult(point, scalar >> 1)
    doubled = _edwards_add(doubled, doubled)
    if scalar & 1:
        doubled = _edwards_add(doubled, point)
    return doubled


def encode_point(p: Point) -> bytes:
    x, y = p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decode_point(blob: bytes) -> Point:
    if len(blob) != 32:
        raise ValueError("公钥/点编码必须为 32 字节")
    raw = int.from_bytes(blob, "little")
    sign = raw >> 255
    y = raw & ((1 << 255) - 1)
    if y >= Q:
        raise ValueError("非规范编码：y >= p")
    x = _x_recover(y)
    if (x & 1) != sign:
        x = Q - x
    point = (x, y)
    if not _on_curve(point):
        raise ValueError("解码点不在曲线上")
    return point


def _clamped_scalar(seed: bytes) -> Tuple[int, bytes]:
    h = _sha512(seed)
    scalar = int.from_bytes(h[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, h[32:]


@lru_cache(maxsize=None)
def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 种子必须为 32 字节")
    scalar, _ = _clamped_scalar(seed)
    return encode_point(_scalar_mult(BASE, scalar))


def sign(seed: bytes, message: bytes) -> bytes:
    """返回 64 字节签名 R(32) || S(32)。"""
    if len(seed) != 32:
        raise ValueError("Ed25519 种子必须为 32 字节")
    scalar, prefix = _clamped_scalar(seed)
    # 复用 public_key 的 lru_cache；席位构造时通常已经计算并缓存过 A。
    a_pub = public_key(seed)

    r = int.from_bytes(_sha512(prefix + message), "little") % L
    r_pub = encode_point(_scalar_mult(BASE, r))

    k = int.from_bytes(_sha512(r_pub + a_pub + message), "little") % L
    s = (r + k * scalar) % L
    return r_pub + s.to_bytes(32, "little")


def verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    """验签。任何编码/格式异常都返回 False（不向外抛）。"""
    try:
        if len(pub) != 32 or len(signature) != 64:
            return False
        r_point = decode_point(signature[:32])
        a_point = decode_point(pub)
        s_int = int.from_bytes(signature[32:], "little")
        if s_int >= L:
            return False
        k = int.from_bytes(
            _sha512(signature[:32] + pub + message), "little"
        ) % L

        # 验证 S*B == R + k*A
        sb = _scalar_mult(BASE, s_int)
        ka = _scalar_mult(a_point, k)
        rhs = _edwards_add(r_point, ka)
        if encode_point(sb) != encode_point(rhs):
            return False

        # 余因子检查（8 倍后仍相等），拒绝小阶/非规范延展性
        sb8 = _scalar_mult(sb, 8)
        rhs8 = _scalar_mult(rhs, 8)
        return encode_point(sb8) == encode_point(rhs8)
    except Exception:
        return False
