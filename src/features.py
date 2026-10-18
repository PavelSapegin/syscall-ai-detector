from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from collections.abc import Callable
from datetime import datetime
from itertools import pairwise
from typing import Any

LOL_BINS = {
    "cmd",
    "powershell",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "wmic",
    "certutil",
    "bitsadmin",
    "schtasks",
    "reg",
    "net",
    "vssadmin",
    "wevtutil",
    "taskkill",
}

TCPIP_PREFIX = "TcpIp"


def parse_ts(ts: str | None) -> datetime:
    if not ts:
        raise ValueError("empty timestamp")
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")


def _basename(s: str) -> str:
    if not s:
        return ""
    s = s.replace("/", "\\")
    parts = s.split("\\")
    return parts[-1].lower()


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in counts.values())


def extract_features(
    events: list[dict[str, Any]], t_start: datetime, horizon: float
) -> dict[str, Any]:
    """Extract features from a list of events within a window.

    events: list of event dicts (full events from JSONL)
    t_start: datetime for window start
    horizon: seconds

    Returns a dict of features (P0 + P1 except network).
    TcpIp* events must not be present in `events` for base features.
    """
    start_ts = t_start.timestamp()
    window_end = start_ts + horizon
    evs: list[dict[str, Any]] = []
    for e in events:
        try:
            ts = parse_ts(e.get("Timestamp"))
        except (TypeError, ValueError):
            continue
        t = ts.timestamp()
        if start_ts <= t <= window_end:
            ev = dict(e)
            ev["_ts_dt"] = ts
            ev["_t_seconds"] = t
            evs.append(ev)

    base_events = [
        e for e in evs if not str(e.get("EventType", "")).startswith(TCPIP_PREFIX)
    ]

    n_events = len(base_events)
    et_counts = Counter(e.get("EventType") for e in base_events)

    duration = max(horizon, 1e-6)
    events_per_sec = n_events / duration

    bins: dict[int, int] = defaultdict(int)
    for e in base_events:
        sec = int(e["_t_seconds"] - start_ts)
        bins[sec] += 1
    max_events_1s_bin = max(bins.values()) if bins else 0

    half = start_ts + horizon / 2
    n_first_half = sum(1 for e in base_events if e["_t_seconds"] <= half)
    frac_events_first_half = n_first_half / n_events if n_events else 0.0

    t_first: dict[Any, float] = {}
    first_ts: float | None = None
    for e in base_events:
        et = e.get("EventType")
        if et not in t_first:
            t_first[et] = e["_t_seconds"] - start_ts
        if first_ts is None or e["_t_seconds"] < first_ts:
            first_ts = e["_t_seconds"]

    times = sorted(e["_t_seconds"] for e in base_events)
    iats = [t2 - t1 for t1, t2 in pairwise(times)] if len(times) >= 2 else []
    iat_mean = sum(iats) / len(iats) if iats else math.nan
    iat_std = (
        (sum((x - iat_mean) ** 2 for x in iats) / len(iats)) ** 0.5
        if iats
        else math.nan
    )
    iat_max = max(iats) if iats else math.nan

    pids = {e.get("ProcessID") for e in base_events if e.get("ProcessID") is not None}
    n_pids = len(pids)
    procstarts = [e for e in base_events if e.get("EventType") == "ProcessStart"]
    spawned: set[Any] = set()
    parent_map: dict[Any, list[Any]] = defaultdict(list)
    for e in procstarts:
        pid = e.get("ProcessID")
        ppid = e.get("ParentProcessID")
        if pid is not None and ppid is not None:
            parent_map[ppid].append(pid)
            spawned.add(pid)
    n_children_spawned = len(spawned)

    def compute_depths(par_map: dict[Any, list[Any]]) -> int:
        children = {pid for chs in par_map.values() for pid in chs}
        roots = [p for p in par_map if p not in children]
        if not roots:
            roots = list(par_map)
        maxd = 0
        for r in roots:
            dq = deque([(r, 0)])
            while dq:
                cur, d = dq.popleft()
                maxd = max(maxd, d)
                for c in par_map.get(cur, []):
                    dq.append((c, d + 1))
        return maxd

    max_tree_depth = compute_depths(parent_map)
    spawn_rate = n_children_spawned / duration if duration else 0.0

    n_lolbin = {f"n_lolbin_{name}": 0 for name in LOL_BINS}
    has_lolbin = {f"has_lolbin_{name}": 0 for name in LOL_BINS}
    for e in procstarts:
        img = _basename(e.get("ImageFileName", ""))
        for name in LOL_BINS:
            if img == name or img.endswith(name + ".exe"):
                n_lolbin[f"n_lolbin_{name}"] += 1
                has_lolbin[f"has_lolbin_{name}"] = 1

    fio_create = [e for e in base_events if e.get("EventType") == "FileIOCreate"]
    fio_write = [e for e in base_events if e.get("EventType") == "FileIOWrite"]
    n_fio_create = len(fio_create)
    n_fio_write = len(fio_write)

    unique_files_created: set[str] = set()
    for e in fio_create:
        fn = e.get("FileName")
        if isinstance(fn, str) and fn:
            unique_files_created.add(fn)
    unique_files_written: set[str] = set()
    for e in fio_write:
        fn = e.get("FileName")
        if isinstance(fn, str) and fn:
            unique_files_written.add(fn)
    n_unique_files_created = len(unique_files_created)
    n_unique_files_written = len(unique_files_written)
    unique_dirs_written: set[str] = set()
    for fn in unique_files_written:
        if "\\" in fn:
            unique_dirs_written.add(fn.rsplit("\\", 1)[0].lower())
    n_unique_dirs_written = len(unique_dirs_written)

    iosizes: list[float] = []
    for e in fio_write:
        size = e.get("IoSize")
        if isinstance(size, (int, float)):
            iosizes.append(float(size))
    bytes_written_total = sum(iosizes)
    iosize_mean = sum(iosizes) / len(iosizes) if iosizes else math.nan
    iosize_std = (
        (sum((x - iosize_mean) ** 2 for x in iosizes) / len(iosizes)) ** 0.5
        if iosizes
        else math.nan
    )
    iosize_max = max(iosizes) if iosizes else 0.0

    seq_count = 0
    total_write_ops = 0
    writes_by_file: dict[str, list[tuple[Any, Any]]] = defaultdict(list)
    for e in fio_write:
        fn = e.get("FileName")
        if not fn:
            continue
        writes_by_file[fn].append((e.get("FileOffset", 0), e.get("IoSize", 0)))
    for ops in writes_by_file.values():
        ops_sorted = sorted(ops, key=lambda x: x[0])
        prev_offset: Any = None
        prev_size: Any = None
        for off, size in ops_sorted:
            total_write_ops += 1
            if prev_offset is not None and prev_offset + (prev_size or 0) == off:
                seq_count += 1
            prev_offset, prev_size = off, size
    frac_sequential_writes = seq_count / total_write_ops if total_write_ops else 0.0

    def path_frac(predicate: Callable[[str], bool]) -> float:
        cnt = 0
        total = 0
        for fn in [*unique_files_created, *unique_files_written]:
            if not fn:
                continue
            total += 1
            if predicate(fn.lower()):
                cnt += 1
        return cnt / total if total else 0.0

    frac_path_system = path_frac(lambda p: "\\windows\\system32" in p)
    frac_path_programdata = path_frac(lambda p: "\\programdata" in p)
    frac_path_programfiles = path_frac(lambda p: "\\programfiles" in p)
    frac_path_temp = path_frac(lambda p: "\\temp" in p or "\\tmp" in p)
    frac_path_appdata_other = path_frac(
        lambda p: "\\appdata\\roaming" in p or "\\appdata\\local" in p
    )
    frac_path_userdocs = path_frac(
        lambda p: (
            "\\users" in p
            and any(
                x in p
                for x in ["\\documents", "\\desktop", "\\downloads", "\\pictures"]
            )
        )
    )
    frac_path_startup = path_frac(lambda p: "\\startup" in p)
    frac_path_unc = path_frac(lambda p: p.startswith("\\\\"))

    path_depths: list[int] = []
    for fn in [*unique_files_created, *unique_files_written]:
        if not fn:
            continue
        parts = [p for p in fn.replace("/", "\\").split("\\") if p]
        path_depths.append(len(parts))
    mean_path_depth = sum(path_depths) / len(path_depths) if path_depths else math.nan

    exts: set[str] = set()
    exec_exts = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".scr"}
    created_exts: list[str] = []
    for fn in unique_files_created:
        if not fn or "." not in fn:
            continue
        ext = "." + fn.lower().rsplit(".", 1)[1]
        created_exts.append(ext)
        exts.add(ext)
    n_distinct_extensions_created = len(exts)
    frac_exec_ext_created = (
        sum(1 for e in created_exts if e in exec_exts) / len(created_exts)
        if created_exts
        else 0.0
    )

    basename_map: dict[str, set[str]] = defaultdict(set)
    for fn in unique_files_created:
        if not fn:
            continue
        b = fn.rsplit("\\", 1)[-1].lower()
        d = fn.rsplit("\\", 1)[0].lower() if "\\" in fn else ""
        basename_map[b].add(d)
    max_same_basename_across_dirs = max(
        (len(s) for s in basename_map.values()), default=0
    )

    entropies: list[float] = []
    for fn in unique_files_created:
        name = fn.rsplit("\\", 1)[-1]
        if "." in name:
            name = name.rsplit(".", 1)[0]
        entropies.append(_entropy(name))
    mean_filename_entropy = sum(entropies) / len(entropies) if entropies else math.nan

    reg_create = [e for e in base_events if e.get("EventType") == "RegistryCreate"]
    reg_set = [e for e in base_events if e.get("EventType") == "RegistrySetValue"]
    n_reg_create = len(reg_create)
    n_reg_setvalue = len(reg_set)
    unique_reg_keys: set[str] = set()
    for e in [*reg_create, *reg_set]:
        key = e.get("KeyName")
        if key:
            unique_reg_keys.add(key)
    n_unique_reg_keys = len(unique_reg_keys)

    pers_keys = [
        "\\run",
        "\\runonce",
        "services\\",
        "winlogon",
        "image file execution options",
        "appinit_dlls",
        "startup",
    ]
    n_reg_persistence = 0
    for k in unique_reg_keys:
        kl = k.lower()
        if any(pk in kl for pk in pers_keys):
            n_reg_persistence += 1
    n_reg_defender_tamper = sum(
        1
        for k in unique_reg_keys
        if "policies\\microsoft\\windows defender" in k.lower()
    )
    frac_reg_hklm = sum(
        1 for k in unique_reg_keys if k.upper().startswith("HKLM")
    ) / max(1, n_unique_reg_keys)

    total_et = sum(et_counts.values())
    event_type_entropy = 0.0
    if total_et > 0:
        for v in et_counts.values():
            p = v / total_et
            event_type_entropy -= p * math.log2(p) if p > 0 else 0.0

    n_events_le_1s = sum(1 for e in base_events if e["_t_seconds"] - start_ts <= 1.0)
    n_events_le_2s = sum(1 for e in base_events if e["_t_seconds"] - start_ts <= 2.0)
    n_events_le_5s = sum(1 for e in base_events if e["_t_seconds"] - start_ts <= 5.0)

    features = {
        "n_events": n_events,
        **{f"n_{k}": v for k, v in et_counts.items()},
        "events_per_sec": events_per_sec,
        "max_events_1s_bin": max_events_1s_bin,
        "frac_events_first_half": frac_events_first_half,
        **{f"t_first_{k}": v for k, v in t_first.items()},
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "iat_max": iat_max,
        "n_pids": n_pids,
        "n_children_spawned": n_children_spawned,
        "max_tree_depth": max_tree_depth,
        "spawn_rate": spawn_rate,
        **n_lolbin,
        **has_lolbin,
        "n_fio_create": n_fio_create,
        "n_fio_write": n_fio_write,
        "n_unique_files_created": n_unique_files_created,
        "n_unique_files_written": n_unique_files_written,
        "n_unique_dirs_written": n_unique_dirs_written,
        "bytes_written_total": bytes_written_total,
        "iosize_mean": iosize_mean,
        "iosize_std": iosize_std,
        "iosize_max": iosize_max,
        "frac_sequential_writes": frac_sequential_writes,
        "frac_path_system": frac_path_system,
        "frac_path_programdata": frac_path_programdata,
        "frac_path_programfiles": frac_path_programfiles,
        "frac_path_temp": frac_path_temp,
        "frac_path_appdata_other": frac_path_appdata_other,
        "frac_path_userdocs": frac_path_userdocs,
        "frac_path_startup": frac_path_startup,
        "frac_path_unc": frac_path_unc,
        "mean_path_depth": mean_path_depth,
        "n_distinct_extensions_created": n_distinct_extensions_created,
        "frac_exec_ext_created": frac_exec_ext_created,
        "max_same_basename_across_dirs": max_same_basename_across_dirs,
        "mean_filename_entropy": mean_filename_entropy,
        "n_reg_create": n_reg_create,
        "n_reg_setvalue": n_reg_setvalue,
        "n_unique_reg_keys": n_unique_reg_keys,
        "n_reg_persistence": n_reg_persistence,
        "n_reg_defender_tamper": n_reg_defender_tamper,
        "frac_reg_hklm": frac_reg_hklm,
        "event_type_entropy": event_type_entropy,
        "write_to_create_ratio": (n_fio_write / n_fio_create)
        if n_fio_create
        else math.nan,
        "new_dirs_per_sec": n_unique_dirs_written / duration if duration else 0.0,
        "n_events_le_1s": n_events_le_1s,
        "n_events_le_2s": n_events_le_2s,
        "n_events_le_5s": n_events_le_5s,
    }

    return features
