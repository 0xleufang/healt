import os
import json
from pathlib import Path
from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = str(PROJECT_ROOT / "config.json")
DEFAULT_LOG_PATH = str(PROJECT_ROOT / "security_alerts.log")

DEFAULT_CONFIG = {
    "refresh_interval": 1.0,
    "log_file": DEFAULT_LOG_PATH,
    "monitored_services": ["sshd", "dockerd", "nginx", "cloudflared"],
    "safe_ports": [],
    "fim_files": ["/etc/passwd", "/etc/sudoers"],
    "canary_watch_dirs": [
        str(PROJECT_ROOT),
    ],
    "canary_filename": ".healt_canary_trap.txt",
    "canary_burst_threshold": 15,
    "canary_burst_window_sec": 5.0,
    "blacklist_keywords": [
        "xmrig", "cpuminer", "meterpreter", "rev_shell",
        "keylogger", "reverse_shell", "backdoor", "c2_agent", "nc -e"
    ],
    "thresholds": {
        "cpu_warn": 80.0,
        "ram_warn": 80.0,
        "disk_crit": 90.0
    }
}


def _resolve_log_path(log_file_value: str) -> str:
    p = Path(log_file_value)
    if p.is_absolute():
        return str(p)
    return str(PROJECT_ROOT / p)


def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    resolved_path = Path(config_path)
    if not resolved_path.is_absolute():
        if not resolved_path.exists() and (PROJECT_ROOT / resolved_path).exists():
            resolved_path = PROJECT_ROOT / resolved_path

    if not resolved_path.exists():
        try:
            resolved_path.parent.mkdir(parents=True, exist_ok=True)
            with open(resolved_path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
        except OSError:
            pass
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))
        cfg["log_file"] = _resolve_log_path(cfg["log_file"])
        return cfg

    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
            merged = json.loads(json.dumps(DEFAULT_CONFIG))
            if isinstance(user_cfg, dict):
                for k, v in user_cfg.items():
                    if k == "thresholds" and isinstance(v, dict):
                        merged["thresholds"].update(v)
                    else:
                        merged[k] = v
            merged["log_file"] = _resolve_log_path(merged["log_file"])
            return merged
    except Exception:
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))
        cfg["log_file"] = _resolve_log_path(cfg["log_file"])
        return cfg


CONFIG = load_config()
