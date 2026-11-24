"""60000 条记录比对的精确计数与等价性测试（用较小样本验证逻辑 + 一次全量冒烟）。"""
import unittest

from iso_drill.scale_diff import (
    TOTAL_RECORDS,
    full_compare,
    generate_records,
    incremental_affected_compare,
    run_scale_benchmark,
)


class TestScaleDiffSmall(unittest.TestCase):
    def test_small_sample_counts_and_equivalence(self):
        # 用小样本验证计数口径（不强制 60000）
        old = generate_records(2000, mutate=False)
        new = generate_records(2000, mutate=True)
        full, fs = full_compare(old, new)
        inc, istats, meta = incremental_affected_compare(old, new)
        self.assertEqual(fs.record_comparisons, 2000)
        # 20 组、每组 100；受影响两组 => 200 条记录比对
        self.assertEqual(istats.record_comparisons, 200)
        self.assertEqual(istats.group_root_comparisons, 20)
        self.assertEqual(meta["groups_total"], 20)
        self.assertTrue(meta["root_detection_matches_declared"])
        self.assertEqual(full, inc)
        self.assertGreater(len(full), 0)


class TestScaleBenchmark60k(unittest.TestCase):
    def test_60000_report_counts(self):
        rep = run_scale_benchmark(TOTAL_RECORDS)
        self.assertEqual(rep["total_simulated_records"], 60000)
        self.assertEqual(rep["full"]["record_comparisons"], 60000)
        self.assertEqual(rep["incremental"]["group_root_comparisons_stage1"], 20)
        # 60000 / 20 组 = 3000/组，两个受影响组 = 6000
        self.assertEqual(rep["incremental"]["record_comparisons_stage2"], 6000)
        self.assertEqual(rep["incremental"]["total_record_hash_comparisons"], 6000)
        self.assertTrue(rep["equivalent_change_sets"])
        self.assertEqual(rep["actual_changed_records"], 240)


if __name__ == "__main__":
    unittest.main()
