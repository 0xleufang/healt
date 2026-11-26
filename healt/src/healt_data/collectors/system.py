import os
import time
from datetime import timedelta
import psutil


def get_uptime_str():
    """Mendapatkan lama waktu sistem menyala"""
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_time)
        td = timedelta(seconds=uptime_seconds)
        days = td.days
        hours, remainder = divmod(td.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        return f"{days}d {hours}h {minutes}m"
    except Exception:
        return "N/A"


def get_inodes_usage():
    """Kalkulasi pemakaian Inode pada partisi root / (Linux/macOS)"""
    try:
        if hasattr(os, "statvfs"):
            st = os.statvfs('/')
            if st.f_files > 0:
                inodes_used_pct = ((st.f_files - st.f_ffree) / st.f_files) * 100
                return f"{inodes_used_pct:.1f}%"
    except Exception:
        pass
    return "N/A (Non-POSIX)"


def get_active_sessions():
    try:
        users = psutil.users()
        if not users:
            return "none / background"
        active = list(set([u.name for u in users]))
        return ", ".join(active)
    except Exception:
        return "N/A"
