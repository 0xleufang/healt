import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

import psutil
from rich.console import Console
from rich.live import Live

from healt_data import config
from healt_data.collectors.fim import init_fim_baselines
from healt_data.collectors.network import get_network_and_disk_speed
from healt_data.sandbox import (
    calculate_security_rate,
    print_siem_scan_report,
    run_sandbox_workflow,
    sanitize_repo_name,
    scan_workspace_structured,
)
from healt_data.ui.dashboard import generate_dashboard

console = Console()


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sys-Sentinel v4.0 - Lightweight Terminal System & Security Monitor + Repo Sandbox"
    )
    parser.add_argument(
        "repo",
        nargs="?",
        default=None,
        help="Opsional: URL repo Git (mis. github.com/user/repo) untuk diuji di container sandbox dulu",
    )
    parser.add_argument(
        "--scan-dir",
        type=str,
        default=None,
        help="Opsional: Pindai direktori lokal secara statis tanpa clone repositori",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=config.CONFIG["refresh_interval"],
        help="Refresh interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=config.DEFAULT_CONFIG_PATH,
        help="Path to custom config.json",
    )
    parser.add_argument(
        "--engine",
        choices=["auto", "docker", "podman"],
        default="auto",
        help="Container engine for sandbox mode",
    )
    parser.add_argument(
        "--image",
        default="python:3.12-slim",
        help="Base container image for sandbox mode",
    )
    parser.add_argument(
        "--install-cmd",
        default="",
        help="Optional install command inside sandbox container",
    )
    parser.add_argument(
        "--test-cmd",
        default="",
        help="Optional offline smoke test command inside sandbox container",
    )
    parser.add_argument(
        "--shell",
        action="store_true",
        help="Open interactive shell inside sandbox container after clone/install",
    )
    parser.add_argument(
        "--dest",
        default=None,
        help="Folder tujuan di host (default: folder kerja aktif saat ini)",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Jalankan 'pip install --no-build-isolation --no-deps .' di folder repo setelah diizinkan",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing destination folder on host / paksa lanjut saat uji sampel",
    )
    parser.add_argument(
        "--memory",
        default="1g",
        help="Container memory limit (default: 1g)",
    )
    parser.add_argument(
        "--cpus",
        default="1.0",
        help="Container CPU limit (default: 1.0)",
    )
    parser.add_argument(
        "--pids-limit",
        type=int,
        default=128,
        help="Container PIDs limit (default: 128)",
    )
    return parser.parse_args(argv)


def _run_local_dir_scan(raw_dir: str) -> int:
    target_path = Path(raw_dir).expanduser().resolve()
    if not target_path.exists():
        console.print(f"[red][ERR] Direktori tidak ditemukan: {target_path}[/red]")
        return 1
    if not target_path.is_dir():
        console.print(f"[red][ERR] Target bukan direktori: {target_path}[/red]")
        return 1

    findings = scan_workspace_structured(target_path)
    rate_info = calculate_security_rate(findings)
    print_siem_scan_report(findings, rate_info)

    if any(f.get("rule_id") == "EXEC-REVSHELL-001" for f in findings):
        console.print(
            "[bold white on red][AUTO-CLOSE][EXEC-REVSHELL-001] Indikasi reverse shell terdeteksi pada direktori lokal.[/bold white on red]"
        )
        return 3

    return 0 if rate_info["allowed"] else 2


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.config != config.DEFAULT_CONFIG_PATH:
        config.CONFIG = config.load_config(args.config)
        init_fim_baselines(config.CONFIG["fim_files"])

    if args.scan_dir:
        code = _run_local_dir_scan(args.scan_dir)
        sys.exit(code)

    if args.repo:
        target_parent = Path(args.dest).expanduser() if args.dest else Path.cwd()
        repo_folder_name = sanitize_repo_name(args.repo)
        code = run_sandbox_workflow(
            raw_repo_url=args.repo,
            engine_pref=args.engine,
            image=args.image,
            install_cmd=args.install_cmd,
            test_cmd=args.test_cmd,
            shell=args.shell,
            dest=str(target_parent),
            force=args.force,
            memory=args.memory,
            cpus=args.cpus,
            pids_limit=args.pids_limit,
        )
        promoted_dir = target_parent / repo_folder_name
        if code == 0 and args.install and promoted_dir.exists():
            console.print(f"[cyan][*] Menjalankan instalasi lokal di {promoted_dir}...[/cyan]")
            res = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--no-build-isolation", "--no-deps", "."],
                cwd=str(promoted_dir),
                check=False,
            )
            if res.returncode != 0:
                console.print(f"[red][!] Instalasi lokal gagal (exit code {res.returncode}).[/red]")
                sys.exit(res.returncode)
            console.print("[bold green][+] Instalasi lokal selesai.[/bold green]")
        sys.exit(code)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        console.print(
            "[yellow][!] Notice: Running without root (sudo). Some port PIDs and system files may be restricted.[/yellow]"
        )
        time.sleep(1.2)

    try:
        psutil.cpu_percent()
        for _ in psutil.process_iter(["cpu_percent"]):
            pass
        get_network_and_disk_speed()
        time.sleep(0.5)
        with Live(generate_dashboard(), refresh_per_second=max(1, int(1 / args.interval)), screen=True) as live:
            while True:
                time.sleep(args.interval)
                live.update(generate_dashboard())
    except KeyboardInterrupt:
        console.print("\n[bold cyan][+] Sys-Sentinel Session Terminated Cleanly.[/bold cyan]")
        sys.exit(0)


def entrypoint():
    """Entrypoint konsisten untuk perintah 'healt' dan 'app.py'."""
    main()


if __name__ == "__main__":
    entrypoint()
