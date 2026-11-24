#!/usr/bin/env python3
"""原生 Windows / Python 3.12 标准库离线演练入口。

双击或命令行运行：
    py -3.12 run_drill.py
    python run_drill.py

可选：
    python run_drill.py --work artifacts\\run
    python run_drill.py --scale 60000
"""
import sys
from pathlib import Path

# 允许在未 pip install 的情况下，从仓库根直接运行本脚本
sys.path.insert(0, str(Path(__file__).resolve().parent))

from iso_drill.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
