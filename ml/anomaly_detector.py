"""
Optional local ML helper for anomaly scoring.
Run standalone to score a small set of local observations.
"""

from __future__ import annotations

import json
from pathlib import Path
from statistics import mean, pstdev


INPUT_PATH = Path("sample_data/telemetry.json")
OUTPUT_PATH = Path("sample_data/anomaly_scores.json")


def zscore(value: float, avg: float, std: float) -> float:
    if std == 0:
        return 0.0
    return abs((value - avg) / std)


def run() -> None:
    if not INPUT_PATH.exists():
        example = [
            {"ts": "2026-02-14T12:00:00Z", "cpu": 18.5, "mem": 34.1, "file_changes": 1},
            {"ts": "2026-02-14T12:01:00Z", "cpu": 19.7, "mem": 35.3, "file_changes": 0},
            {"ts": "2026-02-14T12:02:00Z", "cpu": 82.4, "mem": 70.9, "file_changes": 11},
        ]
        INPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        INPUT_PATH.write_text(json.dumps(example, indent=2), encoding="utf-8")

    telemetry = json.loads(INPUT_PATH.read_text(encoding="utf-8"))

    cpus = [row["cpu"] for row in telemetry]
    mems = [row["mem"] for row in telemetry]
    files = [row["file_changes"] for row in telemetry]

    cpu_avg, cpu_std = mean(cpus), pstdev(cpus)
    mem_avg, mem_std = mean(mems), pstdev(mems)
    file_avg, file_std = mean(files), pstdev(files)

    scored = []
    for row in telemetry:
        score = (
            zscore(row["cpu"], cpu_avg, cpu_std)
            + zscore(row["mem"], mem_avg, mem_std)
            + zscore(row["file_changes"], file_avg, file_std)
        ) / 3
        scored.append({**row, "anomaly_score": round(score, 4)})

    OUTPUT_PATH.write_text(json.dumps(scored, indent=2), encoding="utf-8")
    print(f"Wrote anomaly scores: {OUTPUT_PATH}")


if __name__ == "__main__":
    run()
