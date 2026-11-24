"""Ed25519 RFC 8032 已知答案向量 + PKI 根分离测试。"""
import unittest

from iso_drill import ed25519
from iso_drill.errors import SameRootControllerError
from iso_drill.pki import (
    create_same_root_pair,
    create_separated_dual_control,
    verify_certificate,
)
from iso_drill.approval import build_approval, evaluate_approval
from iso_drill import GROUP_BENCH_01


class TestEd25519Vectors(unittest.TestCase):
    def test_rfc8032_vector1_empty_message(self):
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        expect_pub = (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        expect_sig = (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        pub = ed25519.public_key(seed)
        self.assertEqual(pub.hex(), expect_pub)
        sig = ed25519.sign(seed, b"")
        self.assertEqual(sig.hex(), expect_sig)
        self.assertTrue(ed25519.verify(pub, b"", sig))

    def test_rfc8032_vector2_one_byte(self):
        seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        expect_pub = (
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        )
        expect_sig = (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
            "a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        msg = bytes.fromhex("72")
        pub = ed25519.public_key(seed)
        self.assertEqual(pub.hex(), expect_pub)
        self.assertEqual(ed25519.sign(seed, msg).hex(), expect_sig)
        self.assertTrue(ed25519.verify(pub, msg, bytes.fromhex(expect_sig)))

    def test_tamper_rejected(self):
        seed = bytes(range(32))
        pub = ed25519.public_key(seed)
        sig = ed25519.sign(seed, b"migration-approval")
        self.assertTrue(ed25519.verify(pub, b"migration-approval", sig))
        self.assertFalse(ed25519.verify(pub, b"migration-approva!", sig))
        bad = bytearray(sig)
        bad[10] ^= 0x01
        self.assertFalse(ed25519.verify(pub, b"migration-approval", bytes(bad)))


class TestPKISeparation(unittest.TestCase):
    def test_separated_roots_certs_verify(self):
        dual = create_separated_dual_control()
        verify_certificate(dual.procurement.cert, dual.roots)
        verify_certificate(dual.safety.cert, dual.roots)
        self.assertNotEqual(
            dual.procurement.cert["root_id"], dual.safety.cert["root_id"]
        )

    def test_same_root_cannot_hold_both_seats(self):
        roots, proc, safety = create_same_root_pair()
        # 构造批准时即应拒绝
        with self.assertRaises(SameRootControllerError):
            build_approval(
                step_id="x", seq=1, config_id="C", target_digest="a" * 64,
                predecessor_digest="b" * 64, target_group=GROUP_BENCH_01,
                policy_gen=2, procurement=proc, safety=safety,
            )

    def test_evaluate_flags_same_root_even_if_forged_approval(self):
        # 手工拼一个同根“批准”，evaluate 必须报告根分离检查失败
        roots, proc, safety = create_same_root_pair()
        # 绕过 build_approval 的构造期检查，直接用底层签名拼
        from iso_drill.encoding import canonical_json
        payload = {
            "schema": "iso-drill/migration-approval/v1",
            "approval_id": "APR-deadbeefdeadbeef",
            "step_id": "x", "seq": 1, "config_id": "C",
            "target_digest": "a" * 64, "predecessor_digest": "b" * 64,
            "target_group": GROUP_BENCH_01, "policy_gen": 2, "statement": "",
        }
        sb = canonical_json(payload)
        approval = {
            "payload": payload,
            "procurement": {"seat_id": proc.seat_id, "cert": proc.cert,
                            "sig": proc.sign(sb).hex()},
            "safety": {"seat_id": safety.seat_id, "cert": safety.cert,
                       "sig": safety.sign(sb).hex()},
        }
        rep = evaluate_approval(approval, roots)
        self.assertFalse(rep["valid"])
        self.assertTrue(any("根控制人" in e for e in rep["errors"]))


if __name__ == "__main__":
    unittest.main()
