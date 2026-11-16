"""全系统命令巡检脚本的回归测试（不启动命令，只跑静态解析）。"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_sweep_static_report_is_consistent(tmp_path: Path) -> None:
    report_path = tmp_path / "health.json"
    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "check_all_commands.py"), "--no-exec", "--json", str(report_path)],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    # 有坏命令时脚本退 1，这是设计；关键是报告本身完整
    assert proc.returncode in (0, 1), proc.stdout + proc.stderr
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["command_names"] > 100, "发现到的命令太少，PATH 扫描异常"
    assert report["records"], "没有逐命令记录"
    assert set(report["counts"]) <= {"ok", "broken", "hang", "skipped"}
    assert all(str(record["status"]) != "broken" or record.get("reason") for record in report["records"])
    for item in report["broken_candidates"]:
        assert item.get("path") and item.get("reason"), item
        assert item.get("group"), item
