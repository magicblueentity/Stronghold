from __future__ import annotations

import sys


def compute_score(suspicious: int, high_memory: int, file_anomalies: int) -> float:
    # Lightweight offline heuristic that can be replaced with a real model.
    return min(100.0, suspicious * 3.5 + high_memory * 2.0 + file_anomalies * 6.0)


def main() -> None:
    if len(sys.argv) < 2:
        print("0.0")
        return

    parts = sys.argv[1].strip().split()
    if len(parts) != 3:
        print("0.0")
        return

    try:
        suspicious = int(parts[0])
        high_memory = int(parts[1])
        file_anomalies = int(parts[2])
    except ValueError:
        print("0.0")
        return

    print(f"{compute_score(suspicious, high_memory, file_anomalies):.2f}")


if __name__ == "__main__":
    main()
