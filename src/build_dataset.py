from __future__ import annotations

import argparse
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from tqdm import tqdm

from features import extract_features, parse_ts

TCPIP_PREFIX = "TcpIp"

HORIZONS = [2, 5, 10, 30]


def is_network_event(ev: dict[str, Any]) -> bool:
    return str(ev.get("EventType", "")).startswith(TCPIP_PREFIX)


def read_events_stream(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def get_process_family_pids(
    events: list[dict[str, Any]], root_pid: int | None
) -> set[int]:
    """Возвращает root_pid и все рекурсивно порожденные им дочерние PID."""
    if root_pid is None:
        return set()
    family = {root_pid}
    changed = True
    while changed:
        changed = False
        for e in events:
            if e.get("EventType") == "ProcessStart":
                ppid = e.get("ParentProcessID")
                pid = e.get("ProcessID")
                if ppid in family and pid is not None and pid not in family:
                    family.add(pid)
                    changed = True
    return family


def build_samples_for_trace(path: Path, group: str) -> list[dict[str, Any]]:
    """Return samples (one or many) extracted from a single trace file.

    Each sample is a dict with metadata and feature placeholders.
    """
    events: list[dict[str, Any]] = []
    earliest_event: dict[str, Any] | None = None
    earliest_ps = None
    earliest_ps_pid = None
    procstarts: list[dict[str, Any]] = []
    total_events = 0
    network_events = 0

    for ev in read_events_stream(path):
        total_events += 1
        if earliest_event is None:
            earliest_event = ev
        event_type = ev.get("EventType")
        if event_type and str(event_type).startswith(TCPIP_PREFIX):
            network_events += 1
        if event_type == "ProcessStart":
            procstarts.append(ev)
            ts = parse_ts(ev.get("Timestamp"))
            if earliest_ps is None or ts < earliest_ps:
                earliest_ps = ts
                earliest_ps_pid = ev.get("ProcessID")
        events.append(ev)

    if total_events == 0 or earliest_event is None:
        return []

    is_malware = "data/collected_traces/malware" in str(path)

    samples: list[dict[str, Any]] = []

    if is_malware:
        t_start = None
        for ev in events:
            if not is_network_event(ev):
                t_start = parse_ts(ev.get("Timestamp"))
                break
        if t_start is None:
            t_start = parse_ts(earliest_event.get("Timestamp"))
            t_start_source = "first_event"
        else:
            t_start_source = "first_event"
        t_start_ps = earliest_ps
        t_start_gap_s = (
            (t_start_ps - t_start).total_seconds()
            if t_start_ps is not None
            else float("nan")
        )
        if earliest_ps_pid is not None:
            root_pid = earliest_ps_pid
        else:
            min_ts = min(parse_ts(e.get("Timestamp")) for e in events)
            pids = {
                e.get("ProcessID")
                for e in events
                if parse_ts(e.get("Timestamp")) == min_ts
            }
            root_pid = next(iter(pids)) if len(pids) == 1 else None
        ambiguous = root_pid is None
        samples.append(
            {
                "trace_file": str(path),
                "group": group,
                "is_malware": True,
                "t_start": t_start,
                "t_start_source": t_start_source,
                "t_start_ps": t_start_ps,
                "t_start_gap_s": t_start_gap_s if not ambiguous else float("nan"),
                "root_pid": root_pid if not ambiguous else None,
                "ambiguous_root": ambiguous,
                "total_events": total_events,
                "events": events,
                "procstarts": procstarts,
            }
        )
    else:
        for ps in procstarts:
            pid = ps.get("ProcessID")
            t_start = parse_ts(ps.get("Timestamp"))
            samples.append(
                {
                    "trace_file": str(path),
                    "group": group,
                    "is_malware": False,
                    "t_start": t_start,
                    "t_start_source": "process_start",
                    "t_start_ps": t_start,
                    "t_start_gap_s": 0.0,
                    "root_pid": pid,
                    "ambiguous_root": False,
                    "total_events": total_events,
                    "events": events,
                    "procstarts": procstarts,
                }
            )
    return samples


def _write_parquet(rows: list[dict[str, Any]], path: Path) -> bool:
    if not rows:
        return True
    try:
        import pandas as pd
    except ImportError:
        return False
    try:
        pd.DataFrame(rows).to_parquet(path, index=False)
    except ImportError:
        return False
    return True


def _write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    import csv

    if not rows:
        return

    all_fieldnames = sorted({k for r in rows for k in r})

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def process_all(traces_root: Path, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    feature_rows: list[dict[str, Any]] = []
    network_rows: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "malware_tstarts": [],
        "t_start_gap_over_1s": [],
        "ambiguous_roots": [],
        "t1003_counts": {},
    }

    for kind in ("malware", "valid"):
        base = traces_root / kind
        if not base.exists():
            continue
        jsonl_paths = sorted(
            Path(root) / fn
            for root, _dirs, files in os.walk(base)
            for fn in files
            if fn.endswith(".jsonl")
        )
        for path in tqdm(jsonl_paths, desc=f"Processing {kind}", unit="file"):
            samples = build_samples_for_trace(path, kind)
            for s in samples:
                if s["is_malware"]:
                    report["malware_tstarts"].append(
                        (
                            s["trace_file"],
                            s["t_start"].isoformat(),
                            s["t_start_ps"].isoformat() if s["t_start_ps"] else None,
                            s.get("t_start_gap_s"),
                            s["total_events"],
                        )
                    )
                    gap = s.get("t_start_gap_s")
                    if gap and s.get("t_start_ps") is not None and gap > 1.0:
                        report["t_start_gap_over_1s"].append(s["trace_file"])
                    if s["ambiguous_root"]:
                        report["ambiguous_roots"].append(s["trace_file"])

                # --- [ИСПРАВЛЕНИЕ 2]: Оставляем только события целевого дерева процессо
                if s["is_malware"] and s.get("ambiguous_root"):
                    # Для малвари, если монитор уже изолировал процесс, берем всё
                    proc_events = s["events"]
                else:
                    family_pids = get_process_family_pids(s["events"], s["root_pid"])
                    proc_events = [
                        e for e in s["events"] if e.get("ProcessID") in family_pids
                    ]

                non_net_events = [e for e in proc_events if not is_network_event(e)]

                for h in HORIZONS:
                    feats = extract_features(non_net_events, s["t_start"], float(h))
                    if feats.get("n_events", 0) == 0:
                        continue

                    # --- [ИСПРАВЛЕНИЕ 3]: Сеть считается СТРОГО внутри горизонта h 
                    start_ts = s["t_start"].timestamp()
                    window_end = start_ts + float(h)

                    h_net_events = []
                    for e in proc_events:
                        if is_network_event(e):
                            try:
                                t = parse_ts(e.get("Timestamp")).timestamp()
                                if start_ts <= t <= window_end:
                                    h_net_events.append(e)
                            except (ValueError, TypeError):
                                continue

                    net_counts = {
                        "n_tcp_connect": sum(
                            1
                            for e in h_net_events
                            if e.get("EventType") == "TcpIpConnect"
                        ),
                        "n_tcp_accept": sum(
                            1
                            for e in h_net_events
                            if e.get("EventType") == "TcpIpAccept"
                        ),
                        "n_tcp_send": sum(
                            1 for e in h_net_events if e.get("EventType") == "TcpIpSend"
                        ),
                        "n_tcp_recv": sum(
                            1 for e in h_net_events if e.get("EventType") == "TcpIpRecv"
                        ),
                        "n_unique_remote_ips": len(
                            {
                                (e.get("RemoteAddress"), e.get("RemotePort"))
                                for e in h_net_events
                                if e.get("RemoteAddress")
                            }
                        ),
                        "bytes_sent": sum(
                            int(e.get("NetworkSize") or 0)
                            for e in h_net_events
                            if e.get("EventType") == "TcpIpSend"
                        ),
                        "bytes_recv": sum(
                            int(e.get("NetworkSize") or 0)
                            for e in h_net_events
                            if e.get("EventType") == "TcpIpRecv"
                        ),
                        "trace_file": s["trace_file"],
                        "root_pid": s["root_pid"],
                    }

                    if Path(s["trace_file"]).name == "T1003.002_Test1.jsonl":
                        key = Path(s["trace_file"]).name
                        counts = report["t1003_counts"].setdefault(key, {})
                        counts["events_le_2s"] = sum(
                            1
                            for e in non_net_events
                            if parse_ts(e.get("Timestamp")).timestamp() - start_ts
                            <= 2.0
                        )
                        counts["events_le_5s"] = sum(
                            1
                            for e in non_net_events
                            if parse_ts(e.get("Timestamp")).timestamp() - start_ts
                            <= 5.0
                        )
                        counts["events_le_10s"] = sum(
                            1
                            for e in non_net_events
                            if parse_ts(e.get("Timestamp")).timestamp() - start_ts
                            <= 10.0
                        )

                    row: dict[str, Any] = {
                        "sample_id": (f"{Path(s['trace_file']).stem}"
                                      f"_{s['root_pid']}_{h}"),
                        "trace_file": s["trace_file"],
                        "root_pid": s["root_pid"],
                        "horizon": h,
                        "label_binary": 1 if s["group"] == "malware" else 0,
                        "group": s["group"],
                    }
                    row["class"] = (
                        s["group"]
                        if s["group"] == "valid"
                        else Path(s["trace_file"]).stem
                    )
                    row.update(
                        {
                            "t_start_source": s["t_start_source"],
                            "t_start_gap_s": s.get("t_start_gap_s"),
                        }
                    )
                    row.update(feats)
                    feature_rows.append(row)
                    network_rows.append(
                        {"sample_id": row["sample_id"], "horizon": h, **net_counts}
                    )

    if not _write_parquet(feature_rows, output_dir / "features.parquet"):
        _write_csv(feature_rows, output_dir / "features.csv")
    if not _write_parquet(network_rows, output_dir / "features_network.parquet"):
        _write_csv(network_rows, output_dir / "features_network.csv")

    with (output_dir / "report.md").open("w", encoding="utf-8") as rf:
        rf.write("# Report\n\n")
        rf.write("## Malware t_start table\n\n")
        rf.write("file | t_start | t_start_ps | t_start_gap_s | n_events\n")
        rf.write("---|---|---|---|---\n")
        rf.writelines(
            f"{row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]}\n"
            for row in report["malware_tstarts"]
        )
        rf.write("\n")
        rf.write("## Traces with t_start_gap_s > 1.0\n")
        rf.writelines(f"- {p}\n" for p in report["t_start_gap_over_1s"])
        rf.write("\n")
        rf.write("## Ambiguous roots\n")
        rf.writelines(f"- {p}\n" for p in report["ambiguous_roots"])
        rf.write("\n")
        rf.write("## T1003.002_Test1 event counts\n")
        for k, v in report["t1003_counts"].items():
            rf.write(
                f"- {k}: events_le_2s={v.get('events_le_2s')}, "
                f"events_le_5s={v.get('events_le_5s')}, "
                f"events_le_10s={v.get('events_le_10s')}\n"
            )

    print(
        "Done. Wrote",
        len(feature_rows),
        "feature rows and",
        len(network_rows),
        "network rows",
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--traces-root",
        default="data/collected_traces",
        help="traces root (default data/collected_traces)",
    )
    ap.add_argument("--output-dir", default="out", help="output dir")
    args = ap.parse_args()
    process_all(Path(args.traces_root), Path(args.output_dir))
