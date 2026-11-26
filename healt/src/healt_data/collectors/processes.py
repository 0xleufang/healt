import os
import psutil
from healt_data import config


def collect_process_telemetry():
    """
    SINGLE-PASS TELEMETRY:
    Mengambil seluruh proses 1 kali per siklus untuk efisiensi CPU maksimal.
    Menghasilkan: (top_processes, active_service_names, detected_threats)
    """
    all_procs = []
    detected_threats = []
    running_names = set()

    kernel_whitelist = ('kworker', 'rcu', 'ksoftirqd', 'kthrotld', 'systemd', 'init', 'dbus')
    current_script = os.path.basename(os.path.abspath(__file__)).lower()
    blacklist = [kw.lower() for kw in config.CONFIG["blacklist_keywords"]]

    for p in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
        try:
            pinfo = p.info
            raw_name = pinfo['name'] or ""
            name_lower = raw_name.lower()
            cmdline_str = " ".join(pinfo['cmdline'] or []).lower()

            running_names.add(name_lower)
            all_procs.append(pinfo)

            # Abaikan proses kernel dan skrip monitor ini sendiri
            if (
                name_lower.startswith(kernel_whitelist)
                or current_script in cmdline_str
                or "app.py" in cmdline_str
                or cmdline_str.strip().endswith("/healt")
            ):
                continue

            for kw in blacklist:
                if kw in name_lower or kw in cmdline_str:
                    detected_threats.append((pinfo['pid'], raw_name, cmdline_str[:30]))
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Urutkan Top 4 proses berdasarkan pemakaian CPU
    top_procs = sorted(
        all_procs,
        key=lambda x: x['cpu_percent'] or 0.0,
        reverse=True
    )[:4]

    return top_procs, running_names, detected_threats
