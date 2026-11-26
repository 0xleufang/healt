import os
import time
import hashlib
from pathlib import Path
from collections import deque
from healt_data import config

_CANARY_HASHES = {}
_CANARY_INITIALIZED = False
_DIR_SNAPSHOTS = {}
_BURST_TIMESTAMPS = deque()


def _sha256_file(filepath: Path):
    try:
        if not filepath.exists() or not filepath.is_file():
            return None
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _get_canary_paths():
    canary_name = config.CONFIG.get("canary_filename", ".healt_canary_trap.txt")
    watch_dirs = config.CONFIG.get("canary_watch_dirs", [])
    paths = []
    for d in watch_dirs:
        p = Path(os.path.expanduser(str(d)))
        if p.exists() and p.is_dir():
            paths.append(p / canary_name)
    return paths


def _ensure_canary_files(create_missing: bool = True):
    canary_paths = _get_canary_paths()
    for cpath in canary_paths:
        if not cpath.exists() and create_missing:
            try:
                cpath.parent.mkdir(parents=True, exist_ok=True)
                token = hashlib.sha256(str(cpath).encode("utf-8")).hexdigest()[:24]
                cpath.write_text(f"SYS-SENTINEL CANARY FILE - DO NOT MODIFY OR DELETE [{token}]\n", encoding="utf-8")
            except OSError:
                pass
        if str(cpath) not in _CANARY_HASHES:
            _CANARY_HASHES[str(cpath)] = _sha256_file(cpath)
    return canary_paths


def _scan_dir_files(directory: Path, max_files: int = 2000):
    """Mengambil snapshot (mtime_ns, size) file di direktori untuk deteksi perubahan/penghapusan massal."""
    snap = {}
    count = 0
    try:
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", ".venv", "venv"}]
            for fname in files:
                fpath = Path(root) / fname
                try:
                    st = fpath.stat()
                    snap[str(fpath)] = (st.st_mtime_ns, st.st_size)
                    count += 1
                    if count >= max_files:
                        return snap
                except OSError:
                    continue
    except OSError:
        pass
    return snap


def init_canary_state():
    """Menginisialisasi baseline canary file dan snapshot direktori awal."""
    global _CANARY_INITIALIZED, _DIR_SNAPSHOTS
    _ensure_canary_files(create_missing=True)
    new_snaps = {}
    for d in config.CONFIG.get("canary_watch_dirs", []):
        dp = Path(os.path.expanduser(str(d)))
        if dp.exists() and dp.is_dir():
            new_snaps[str(dp)] = _scan_dir_files(dp)
    _DIR_SNAPSHOTS = new_snaps
    _CANARY_INITIALIZED = True


def check_canary_and_ransomware():
    """
    Memeriksa:
    1. Apakah canary file hilang atau berubah hash SHA-256.
    2. Apakah terjadi lonjakan modifikasi/penghapusan file (burst) dalam jendela waktu singkat.
    Mengembalikan dict: {"canary_triggered": list[str], "ransomware_burst": bool, "burst_events": int}
    """
    global _CANARY_INITIALIZED, _DIR_SNAPSHOTS
    if not _CANARY_INITIALIZED:
        init_canary_state()

    canary_triggered = []
    canary_paths = _ensure_canary_files(create_missing=False)

    for cpath in canary_paths:
        key = str(cpath)
        expected_hash = _CANARY_HASHES.get(key)
        current_hash = _sha256_file(cpath)

        if not cpath.exists():
            canary_triggered.append(f"DELETED:{cpath.name}")
        elif expected_hash and current_hash and current_hash != expected_hash:
            canary_triggered.append(f"MODIFIED:{cpath.name}")

    # Hitung perubahan/penghapusan file pada direktori yang dipantau
    events_this_tick = 0
    for d in config.CONFIG.get("canary_watch_dirs", []):
        dp = Path(os.path.expanduser(str(d)))
        if not dp.exists() or not dp.is_dir():
            continue
        dkey = str(dp)
        prev_snap = _DIR_SNAPSHOTS.get(dkey, {})
        curr_snap = _scan_dir_files(dp)

        # File yang dihapus atau berubah (mtime / ukuran)
        for fpath_str, old_meta in prev_snap.items():
            if fpath_str not in curr_snap:
                events_this_tick += 1
            elif curr_snap[fpath_str] != old_meta:
                events_this_tick += 1

        _DIR_SNAPSHOTS[dkey] = curr_snap

    now = time.time()
    window = float(config.CONFIG.get("canary_burst_window_sec", 5.0))
    threshold = int(config.CONFIG.get("canary_burst_threshold", 15))

    for _ in range(events_this_tick):
        _BURST_TIMESTAMPS.append(now)

    while _BURST_TIMESTAMPS and (now - _BURST_TIMESTAMPS[0]) > window:
        _BURST_TIMESTAMPS.popleft()

    burst_count = len(_BURST_TIMESTAMPS)
    ransomware_burst = burst_count >= threshold

    return {
        "canary_triggered": canary_triggered,
        "ransomware_burst": ransomware_burst,
        "burst_events": burst_count,
    }
