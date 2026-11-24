"""全部确定性演练场景必须通过（CLI 与测试共用同一套场景函数）。"""
import tempfile
import unittest
from pathlib import Path

from iso_drill.scenarios import (
    scenario_concurrent_preservation,
    scenario_duplicate_digest_race,
    scenario_happy_chain,
    scenario_out_of_band_swap,
    scenario_receipt_crash_before_write,
    scenario_receipt_deleted_after_persist,
    scenario_revoke_preempt,
    scenario_same_number_binding,
)

SCENARIOS = [
    scenario_happy_chain,
    scenario_revoke_preempt,
    scenario_receipt_crash_before_write,
    scenario_receipt_deleted_after_persist,
    scenario_same_number_binding,
    scenario_out_of_band_swap,
    scenario_duplicate_digest_race,
    scenario_concurrent_preservation,
]


class TestScenarios(unittest.TestCase):
    def test_every_scenario_check_passes(self):
        failures = []
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            for fn in SCENARIOS:
                res = fn(base / fn.__name__)
                if not res["ok"]:
                    failed = [c for c in res["checks"] if not c["passed"]]
                    failures.append(
                        f"\n[{res['key']}] {res.get('fatal', '')}\n  "
                        + "\n  ".join(f"{c['name']} :: {c['detail']}" for c in failed)
                    )
        self.assertFalse(failures, "存在未通过场景:" + "".join(failures))


if __name__ == "__main__":
    unittest.main()
