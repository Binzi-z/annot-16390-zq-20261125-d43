"""签名绑定四要素的篡改用例：摘要/目标组/策略代/前驱，任何改动都必须失效。"""
import tempfile
import unittest
from pathlib import Path

from iso_drill.approval import bind_actual_config, evaluate_approval
from iso_drill.configstore import config_bytes
from iso_drill.encoding import canonical_json
from iso_drill.world import build_world


class TestBinding(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self._tmp.name)
        self.world = build_world(self.root)
        self.g = self.world.groups[0]
        self.step = self.world.steps[self.g][1]
        self.approval = self.step.approval

    def tearDown(self):
        self._tmp.cleanup()

    def test_valid_approval(self):
        rep = evaluate_approval(self.approval, self.world.dual.roots)
        self.assertTrue(rep["valid"], rep["errors"])
        bind_actual_config(self.approval, config_bytes(self.step.config))

    def _tampered(self, mutate_payload):
        import copy
        apr = copy.deepcopy(self.approval)
        mutate_payload(apr["payload"])
        # 改 payload 后原签名必然失效
        return evaluate_approval(apr, self.world.dual.roots)

    def test_tamper_target_digest_invalidates_signature(self):
        rep = self._tampered(lambda p: p.update(target_digest="f" * 64))
        self.assertFalse(rep["valid"])

    def test_tamper_group_invalidates_signature(self):
        rep = self._tampered(lambda p: p.update(target_group="grp-other"))
        self.assertFalse(rep["valid"])

    def test_tamper_policy_gen_invalidates_signature(self):
        rep = self._tampered(lambda p: p.update(policy_gen=99))
        self.assertFalse(rep["valid"])

    def test_tamper_predecessor_invalidates_signature(self):
        rep = self._tampered(lambda p: p.update(predecessor_digest="0" * 64))
        self.assertFalse(rep["valid"])

    def test_bind_rejects_wrong_group_content(self):
        import copy
        cfg = copy.deepcopy(self.step.config)
        # 构造一份摘要不同、组也不同的实际文件
        cfg["target_group"] = "grp-other"
        with self.assertRaises(Exception):
            bind_actual_config(self.approval, config_bytes(cfg))

    def test_cross_group_approval_not_valid_for_other_group(self):
        other = self.world.steps[self.world.groups[1]][0].approval
        # 另一个组的批准书本身有效，但其绑定组不是本组
        rep = evaluate_approval(other, self.world.dual.roots)
        self.assertTrue(rep["valid"])
        self.assertNotEqual(other["payload"]["target_group"], self.g)


if __name__ == "__main__":
    unittest.main()
