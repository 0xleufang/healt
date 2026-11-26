from pathlib import Path
from datetime import datetime
from healt_data import config

# --- GLOBAL STATE TRACKING ---
last_logged_alert = ""


def log_alert_to_file(message: str) -> None:
    """Menyimpan log peringatan kritis ke file eksternal (anti-spam duplikat beruntun)"""
    global last_logged_alert
    clean_msg = message.replace("[bold red]", "").replace("[/bold red]", "")
    clean_msg = clean_msg.replace("[bold yellow]", "").replace("[/bold yellow]", "")
    if clean_msg == last_logged_alert:
        return
    last_logged_alert = clean_msg
    try:
        log_path = Path(config.CONFIG["log_file"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {clean_msg}\n")
    except OSError:
        pass
