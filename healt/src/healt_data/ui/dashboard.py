import os
import platform
from datetime import datetime
import psutil
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.align import Align
from rich.text import Text
from healt_data import config
from healt_data.collectors.system import get_uptime_str, get_inodes_usage, get_active_sessions
from healt_data.collectors.network import get_network_and_disk_speed, get_open_listening_ports
from healt_data.collectors.processes import collect_process_telemetry
from healt_data.collectors.fim import check_file_integrity
from healt_data.collectors.canary import check_canary_and_ransomware
from healt_data.analys.health import calculate_dynamic_health

AUTHOR_NAME = "leu_fang"
YT_CHANNEL = config.CONFIG.get("yt_channel", "@leu_fang")


def _format_ports(open_ports, safe_ports):
    if not open_ports:
        return "[dim]none[/dim]"
    badges = []
    for port in open_ports[:6]:
        if port in safe_ports:
            badges.append(f"[green]{port}[/green]")
        else:
            badges.append(f"[bold red]{port}![/bold red]")
    if len(open_ports) > 6:
        badges.append(f"[dim]+{len(open_ports) - 6}[/dim]")
    return ", ".join(badges)


def _format_canary(canary_status):
    if not isinstance(canary_status, dict):
        return "[yellow]UNKNOWN[/yellow]"
    if canary_status.get("ransomware_burst"):
        burst_n = canary_status.get("burst_events", 0)
        return f"[bold red]BURST ({burst_n})[/bold red]"
    if canary_status.get("canary_triggered"):
        return "[bold red]TRIGGERED[/bold red]"
    return "[green]ARMED[/green]"


def generate_dashboard():
    net_sent_spd, net_recv_spd, disk_read_spd, disk_write_spd = get_network_and_disk_speed()
    top_procs, running_names, threats = collect_process_telemetry()
    fim_alerts = check_file_integrity()
    canary_status = check_canary_and_ransomware()

    cpu_pct = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk_path = "C:\\" if platform.system() == "Windows" else "/"
    disk = psutil.disk_usage(disk_path)

    energy_bar, status_text, bar_color, alert_msg = calculate_dynamic_health(
        cpu_pct, ram.percent, disk.percent, threats, fim_alerts, top_procs, canary_status
    )

    layout = Layout()
    layout.split_column(
        Layout(name="author_header", size=3),
        Layout(name="sys_header", size=3),
        Layout(name="middle", ratio=1, minimum_size=15),
        Layout(name="energy_hud", size=6),
    )
    layout["middle"].split_row(
        Layout(name="sys_perf", ratio=1),
        Layout(name="net_disk", ratio=1),
        Layout(name="procs_services", ratio=1),
    )

    # --- AUTHOR HEADER ---
    author_line = (
        f"[bold cyan]SYS-SENTINEL v4.0[/bold cyan]  |  "
        f"AUTHOR: [bold white]{AUTHOR_NAME}[/bold white]  |  "
        f"YOUTUBE: [bold red]{YT_CHANNEL}[/bold red]"
    )
    layout["author_header"].update(
        Panel(
            Align.center(Text.from_markup(author_line, overflow="ellipsis")),
            border_style="cyan",
        )
    )

    # --- SYSTEM & APP HEADER ---
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = platform.node()
    os_info = f"{platform.system()} {platform.release()}"
    sys_line = (
        f"HOST: [bold white]{hostname}[/bold white] ([dim]{os_info}[/dim])  |  "
        f"UPTIME: [bold green]{get_uptime_str()}[/bold green]  |  "
        f"TIME: [bold yellow]{now_str}[/bold yellow]"
    )
    layout["sys_header"].update(
        Panel(
            Align.center(Text.from_markup(sys_line, overflow="ellipsis")),
            border_style="blue",
        )
    )

    # --- PANEL 01: SYSTEM HEALTH ---
    t_sys = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    t_sys.add_column("Key", style="bold green", width=15, no_wrap=True)
    t_sys.add_column("Val", style="white", overflow="ellipsis")

    try:
        load1, load5, load15 = os.getloadavg()
        load_str = f"{load1:.2f} / {load5:.2f} / {load15:.2f}"
    except Exception:
        load_str = "N/A"

    cpu_freq = psutil.cpu_freq()
    freq_str = f"{cpu_freq.current:.0f}MHz" if cpu_freq else "N/A"
    ram_used_mb = ram.used // (1024 ** 2)
    ram_total_mb = ram.total // (1024 ** 2)

    t_sys.add_row("CPU Cores", f"{psutil.cpu_count(logical=True)} Threads")
    t_sys.add_row("CPU Load", f"[bold]{cpu_pct:.1f}%[/bold] @ {freq_str}")
    t_sys.add_row("Load Avg", load_str)
    t_sys.add_row("RAM Used", f"{ram.percent:.1f}% ({ram_used_mb}/{ram_total_mb}MB)")
    t_sys.add_row("SWAP Usage", f"{swap.percent:.1f}%")
    t_sys.add_row("Active Sessions", f"[cyan]{get_active_sessions()}[/cyan]")

    layout["sys_perf"].update(
        Panel(t_sys, title="[bold green][01] SYSTEM HEALTH[/bold green]", border_style="green")
    )

    # --- PANEL 02: I/O, NETWORK & SECURITY GUARDS ---
    t_io = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    t_io.add_column("Key", style="bold cyan", width=15, no_wrap=True)
    t_io.add_column("Val", style="white", overflow="ellipsis")

    open_ports = get_open_listening_ports()
    safe_ports = set(config.CONFIG.get("safe_ports", []))
    disk_used_gb = disk.used // (1024 ** 3)
    disk_total_gb = disk.total // (1024 ** 3)
    fim_count = len(fim_alerts) if fim_alerts else 0
    fim_badge = (
        "[green]VERIFIED[/green]"
        if not fim_alerts
        else f"[bold red]TAMPERED ({fim_count})[/bold red]"
    )

    t_io.add_row("Disk Usage", f"{disk.percent:.1f}% ({disk_used_gb}/{disk_total_gb}GB)")
    t_io.add_row("Inodes Used", str(get_inodes_usage()))
    t_io.add_row("Disk R / W", f"[green]{disk_read_spd:.1f}[/green] / [yellow]{disk_write_spd:.1f} MB/s[/yellow]")
    t_io.add_row("Net Up / Down", f"[cyan]{net_sent_spd:.1f}[/cyan] / [magenta]{net_recv_spd:.1f} KB/s[/magenta]")
    t_io.add_row("Listen Ports", _format_ports(open_ports, safe_ports))
    t_io.add_row("FIM SHA-256", fim_badge)
    t_io.add_row("Canary Guard", _format_canary(canary_status))

    layout["net_disk"].update(
        Panel(t_io, title="[bold cyan][02] I/O & NETWORK[/bold cyan]", border_style="cyan")
    )

    # --- PANEL 03: PROCESSES & MONITORED DAEMONS ---
    t_proc = Table(show_header=True, header_style="bold yellow", box=None, padding=(0, 1), expand=True)
    t_proc.add_column("PID", style="dim", width=6, no_wrap=True)
    t_proc.add_column("PROCESS", style="bold white", overflow="ellipsis")
    t_proc.add_column("CPU%", style="green", width=6, justify="right", no_wrap=True)
    t_proc.add_column("MEM%", style="magenta", width=6, justify="right", no_wrap=True)

    for p in (top_procs or [])[:4]:
        t_proc.add_row(
            str(p.get("pid", "")),
            str(p.get("name", "unknown")),
            f"{float(p.get('cpu_percent') or 0.0):.1f}",
            f"{float(p.get('memory_percent') or 0.0):.1f}",
        )

    t_serv = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    t_serv.add_column("Service", style="bold white", overflow="ellipsis")
    t_serv.add_column("Status", justify="right", width=9, no_wrap=True)

    running_lower = [str(r).lower() for r in (running_names or [])]
    for svc in config.CONFIG.get("monitored_services", []):
        is_online = any(str(svc).lower() in r_name for r_name in running_lower)
        status_badge = "[bold green]ONLINE[/bold green]" if is_online else "[bold red]OFFLINE[/bold red]"
        t_serv.add_row(str(svc), status_badge)

    proc_service_layout = Layout()
    proc_service_layout.split_column(
        Layout(t_proc, size=6),
        Layout(Panel(t_serv, title="[bold yellow]MONITORED DAEMONS[/bold yellow]", border_style="dim")),
    )

    layout["procs_services"].update(
        Panel(proc_service_layout, title="[bold yellow][03] WORKLOADS[/bold yellow]", border_style="yellow")
    )

    # --- PANEL 04: HEALTH & THREAT INTERCEPTOR HUD ---
    threat_count = len(threats) if threats else 0
    log_path_str = str(config.CONFIG.get("log_file", "-"))
    if len(log_path_str) > 36:
        log_path_str = "..." + log_path_str[-33:]

    hud_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    hud_table.add_column("Label", style="bold white", width=15, no_wrap=True)
    hud_table.add_column("Bar", ratio=2, overflow="ellipsis")
    hud_table.add_column("StatusInfo", justify="right", ratio=2, overflow="ellipsis")

    hud_table.add_row(
        "HEALTH SCORE:",
        energy_bar,
        f"STATE: [bold {bar_color}]{status_text}[/bold {bar_color}]  [dim](threats: {threat_count})[/dim]",
    )
    hud_table.add_row(
        "SECURITY SCAN:",
        f"[{bar_color}]{alert_msg}[/{bar_color}]",
        f"[dim]Log: {log_path_str}[/dim]",
    )

    layout["energy_hud"].update(
        Panel(
            hud_table,
            title=f"[bold white][04] HEALTH & THREAT INTERCEPTOR HUD  |  {AUTHOR_NAME}[/bold white]",
            border_style=bar_color,
        )
    )

    return layout
