from healt_data import config
from healt_data.logger import log_alert_to_file


def calculate_dynamic_health(
    cpu_pct,
    ram_pct,
    disk_pct,
    threats,
    fim_alerts,
    top_procs,
    canary_status=None,
):
    canary_status = canary_status or {}
    canary_triggered = canary_status.get("canary_triggered", [])
    ransomware_burst = bool(canary_status.get("ransomware_burst", False))
    burst_events = int(canary_status.get("burst_events", 0))

    usage_penalty = (cpu_pct * 0.35) + (ram_pct * 0.35) + (disk_pct * 0.20)

    if threats:
        usage_penalty += 60
    if fim_alerts:
        usage_penalty += 40
    if canary_triggered:
        usage_penalty += 50
    if ransomware_burst:
        usage_penalty += 50

    has_critical_security_event = bool(threats or fim_alerts or canary_triggered or ransomware_burst)
    health_score = int(max(0, min(100, 100 - usage_penalty)))

    if health_score >= 80 and not has_critical_security_event:
        bar_color = "green"
        status_text = "NOMINAL & SECURE"
    elif 50 <= health_score < 80 and not has_critical_security_event:
        bar_color = "yellow"
        status_text = "MODERATE LOAD"
    else:
        bar_color = "red"
        status_text = "CRITICAL / THREAT ALERT!"

    total_blocks = 25
    filled_blocks = int((health_score / 100) * total_blocks)
    empty_blocks = total_blocks - filled_blocks

    energy_bar = (
        f"[{bar_color}]" + "█" * filled_blocks + f"[/][dim]" + "░" * empty_blocks +
        f"[/] [bold {bar_color}]{health_score}%[/bold {bar_color}]"
    )

    top_proc_name = top_procs[0]['name'] if top_procs else "unknown"
    top_proc_cpu = top_procs[0]['cpu_percent'] or 0.0 if top_procs else 0.0

    if threats:
        pid, pname, _ = threats[0]
        alert_msg = f"[bold red][!] THREAT DETECTED: PID {pid} ({pname}) -> RUN: kill -9 {pid}[/bold red]"
        log_alert_to_file(alert_msg)
    elif ransomware_burst:
        alert_msg = f"[bold red][!] ANTI-RANSOMWARE BURST: {burst_events} file changes/deletes detected![/bold red]"
        log_alert_to_file(alert_msg)
    elif canary_triggered:
        alert_msg = f"[bold red][!] CANARY TRIGGERED: {', '.join(canary_triggered)}![/bold red]"
        log_alert_to_file(alert_msg)
    elif fim_alerts:
        alert_msg = f"[bold red][!] FIM SHA-256 MISMATCH: {', '.join(fim_alerts)} MODIFIED![/bold red]"
        log_alert_to_file(alert_msg)
    elif cpu_pct > config.CONFIG["thresholds"]["cpu_warn"]:
        alert_msg = f"[bold yellow][!] HIGH CPU ({cpu_pct}%): Top culprit '{top_proc_name}' ({top_proc_cpu:.1f}%)[/bold yellow]"
        log_alert_to_file(alert_msg)
    elif ram_pct > config.CONFIG["thresholds"]["ram_warn"]:
        alert_msg = f"[bold yellow][!] HIGH MEMORY ({ram_pct}%): Check active workloads[/bold yellow]"
        log_alert_to_file(alert_msg)
    elif disk_pct > config.CONFIG["thresholds"]["disk_crit"]:
        alert_msg = f"[bold red][!] CRITICAL STORAGE: Root partition at {disk_pct}%[/bold red]"
        log_alert_to_file(alert_msg)
    else:
        alert_msg = "[green][+] SYSTEM HEALTHY: All daemons, hashes & processes verified.[/green]"

    return energy_bar, status_text, bar_color, alert_msg
