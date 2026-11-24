"""决定日志哈希链与篡改检测。"""
import tempfile
import unittest
from pathlib import Path

from iso_drill.errors import JournalTampered
from iso_drill.journal import DecisionLog


class TestJournal(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = Path(self._tmp.name) / "decisions.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def test_append_reload_and_verify(self):
        log = DecisionLog(self.path)
        log.append("A", x=1)
        log.append("B", y=2)
        log2 = DecisionLog(self.path)
        self.assertEqual(len(log2), 2)
        self.assertTrue(log2.verify_chain())
        self.assertEqual(log2.of_kind("B")[0]["y"], 2)

    def test_tamper_content_detected(self):
        log = DecisionLog(self.path)
        log.append("A", approval_id="APR-1")
        log.append("B", approval_id="APR-2")
        lines = self.path.read_text(encoding="utf-8").splitlines()
        # 篡改第一行中的某个字段，保持 JSON 合法
        lines[0] = lines[0].replace("APR-1", "APR-EVIL")
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(JournalTampered):
            DecisionLog(self.path)

    def test_delete_line_breaks_chain(self):
        log = DecisionLog(self.path)
        for i in range(3):
            log.append("A", i=i)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        # 删除中间行 -> prev_hash 断链
        self.path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
        with self.assertRaises(JournalTampered):
            DecisionLog(self.path)


if __name__ == "__main__":
    unittest.main()
