#!/usr/bin/env python3
from __future__ import annotations

import os
import platform
import subprocess
import sys
import threading
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
VENV_DIR = ROOT_DIR / ".venv"
HOME_DIR = Path.home()
HEALT_HOME = HOME_DIR / ".healt"

HOOK_START = "# >>> healt git clone guard >>>"
HOOK_END = "# <<< healt git clone guard <<<"

POSIX_GIT_HOOK = f"""
{HOOK_START}
git() {{
  if [ "$1" = "clone" ]; then
    shift
    for arg in "$@"; do
      case "$arg" in
        -*)
          command git clone "$@"
          return $?
          ;;
      esac
    done
    healt "$@"
    return $?
  fi
  command git "$@"
}}
{HOOK_END}
""".strip()


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def run_cmd(cmd: list[str], log_fn, extra_env: dict[str, str] | None = None) -> bool:
    env = os.environ.copy()
    env["PYTHONWARNINGS"] = "ignore"
    if extra_env:
        env.update(extra_env)

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            clean = line.rstrip()
            if clean:
                log_fn(clean)
        proc.wait()
        return proc.returncode == 0
    except Exception as exc:
        log_fn(f"[ERR] {exc}")
        return False


def ensure_pyproject(log_fn) -> None:
    pyproject = ROOT_DIR / "pyproject.toml"
    if pyproject.exists():
        return
    log_fn("[INF] membuat pyproject.toml...")
    pyproject.write_text(
        """[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "healt"
version = "0.1.0"
description = "Signature scan and sandbox guard before placing external repositories"
requires-python = ">=3.9"
dependencies = ["psutil", "rich"]

[project.scripts]
healt = "healt_data.cli:main"

[tool.setuptools]
package-dir = {"" = "src"}

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
healt_data = ["../rules/*.json"]
""",
        encoding="utf-8",
    )


def ensure_venv(log_fn) -> Path:
    if sys.prefix != sys.base_prefix:
        return Path(sys.executable)

    py_bin = (
        VENV_DIR / "Scripts" / "python.exe"
        if is_windows()
        else VENV_DIR / "bin" / "python"
    )
    if not py_bin.exists():
        log_fn("[INF] menyiapkan virtual environment (.venv)...")
        ok = run_cmd([sys.executable, "-m", "venv", str(VENV_DIR)], log_fn)
        if not ok:
            log_fn("[WRN] gagal membuat .venv, memakai Python sistem.")
            return Path(sys.executable)
    return py_bin


def install_healt(py_bin: Path, log_fn) -> None:
    log_fn("[INF] menginstal dependensi & paket healt...")
    fast_cmds = [
        [str(py_bin), "-m", "pip", "install", "--no-build-isolation", "-e", ".", "-q"],
        [
            str(py_bin),
            "-m",
            "pip",
            "install",
            "--no-build-isolation",
            "--break-system-packages",
            "-e",
            ".",
            "-q",
        ],
    ]
    for cmd in fast_cmds:
        if run_cmd(cmd, log_fn):
            log_fn("[INF] paket healt terpasang.")
            return
    log_fn("[INF] mengunduh dependensi yang diperlukan...")
    fallback_cmds = [
        [str(py_bin), "-m", "pip", "install", "-e", ".", "-q"],
        [str(py_bin), "-m", "pip", "install", "--break-system-packages", "-e", ".", "-q"],
    ]
    for cmd in fallback_cmds:
        if run_cmd(cmd, log_fn):
            log_fn("[INF] paket healt terpasang.")
            return

    log_fn("[WRN] pip belum berhasil penuh; aplikasi tetap bisa dijalankan via app.py.")


def setup_launcher_and_hooks(py_bin: Path, log_fn) -> None:
    HEALT_HOME.mkdir(parents=True, exist_ok=True)

    if is_windows():
        bin_dir = Path(os.environ.get("LOCALAPPDATA", str(HOME_DIR / "AppData" / "Local"))) / "healt" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        bat_file = bin_dir / "healt.bat"
        app_py = ROOT_DIR / "app.py"
        bat_file.write_text(
            f'@echo off\r\n"{py_bin}" "{app_py}" %*\r\n',
            encoding="utf-8",
        )
        log_fn(f"[INF] launcher dibuat: {bat_file}")
        return

    local_bin = HOME_DIR / ".local" / "bin"
    local_bin.mkdir(parents=True, exist_ok=True)
    target_bin = local_bin / "healt"

    venv_script = py_bin.parent / "healt"
    app_py = ROOT_DIR / "app.py"

    if venv_script.exists():
        if target_bin.is_symlink() or target_bin.exists():
            target_bin.unlink()
        target_bin.symlink_to(venv_script)
        log_fn(f"[INF] perintah global terhubung ke: {venv_script}")
    else:
        target_bin.write_text(
            f'#!/usr/bin/env bash\nexec "{py_bin}" "{app_py}" "$@"\n',
            encoding="utf-8",
        )
        os.chmod(target_bin, 0o755)
        log_fn(f"[INF] wrapper dibuat di: {target_bin}")

    def patch_rc(rc_path: Path) -> None:
        if not rc_path.parent.exists():
            return
        old = rc_path.read_text(encoding="utf-8") if rc_path.exists() else ""
        new = old
        if HOOK_START not in new:
            sep = "\n\n" if new and not new.endswith("\n") else ("\n" if new else "")
            new += f"{sep}{POSIX_GIT_HOOK}\n"
        path_export = 'export PATH="$HOME/.local/bin:$PATH"'
        if path_export not in new:
            new += f"\n{path_export}\n"
        if new != old:
            rc_path.write_text(new, encoding="utf-8")
            log_fn(f"[INF] hook git clone & PATH diperbarui di: {rc_path}")

    shell_name = os.path.basename(os.environ.get("SHELL", "/bin/bash"))
    if shell_name == "zsh":
        patch_rc(HOME_DIR / ".zshrc")
    else:
        patch_rc(HOME_DIR / ".bashrc")
        if (HOME_DIR / ".zshrc").exists():
            patch_rc(HOME_DIR / ".zshrc")


def run_full_setup(log_fn) -> None:
    log_fn("[INF] memulai setup healt...")
    ensure_pyproject(log_fn)
    py_bin = ensure_venv(log_fn)
    install_healt(py_bin, log_fn)
    setup_launcher_and_hooks(py_bin, log_fn)
    log_fn("[INF] selesai. buka terminal baru lalu ketik: healt --help")


def launch_gui() -> None:
    import tkinter as tk
    from tkinter import scrolledtext

    root = tk.Tk()
    root.title("healt - Auto Installer")
    root.geometry("620x400")
    root.configure(bg="#111317")

    header = tk.Label(
        root,
        text="healt Setup Wizard",
        font=("TkDefaultFont", 14, "bold"),
        fg="#e6edf3",
        bg="#111317",
    )
    header.pack(pady=(14, 4))

    subtitle = tk.Label(
        root,
        text="Klik tombol di bawah untuk menginstal dependensi & menyiapkan perintah healt otomatis.",
        font=("TkDefaultFont", 9),
        fg="#8b949e",
        bg="#111317",
    )
    subtitle.pack(pady=(0, 10))

    log_box = scrolledtext.ScrolledText(
        root,
        height=14,
        bg="#0d1117",
        fg="#c9d1d9",
        insertbackground="#c9d1d9",
        font=("TkFixedFont", 9),
        relief="flat",
        padx=10,
        pady=8,
    )
    log_box.pack(fill="both", expand=True, padx=14, pady=(0, 12))
    log_box.configure(state="disabled")

    def append_log(msg: str) -> None:
        def _write() -> None:
            log_box.configure(state="normal")
            log_box.insert("end", msg + "\n")
            log_box.see("end")
            log_box.configure(state="disabled")

        root.after(0, _write)

    btn_frame = tk.Frame(root, bg="#111317")
    btn_frame.pack(pady=(0, 14))

    install_btn = tk.Button(
        btn_frame,
        text="Install Sekarang",
        font=("TkDefaultFont", 10, "bold"),
        bg="#238636",
        fg="#ffffff",
        activebackground="#2ea043",
        activeforeground="#ffffff",
        relief="flat",
        padx=18,
        pady=8,
        cursor="hand2",
    )
    install_btn.pack(side="left", padx=6)

    def on_install() -> None:
        install_btn.configure(state="disabled", text="Menginstal...")

        def worker() -> None:
            try:
                run_full_setup(append_log)
            finally:
                root.after(0, lambda: install_btn.configure(state="normal", text="Install Ulang"))

        threading.Thread(target=worker, daemon=True).start()

    install_btn.configure(command=on_install)
    root.mainloop()


def main() -> None:
    if "--cli" in sys.argv:
        run_full_setup(print)
        return
    has_display = is_windows() or bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if has_display:
        try:
            launch_gui()
            return
        except Exception:
            pass

    run_full_setup(print)


if __name__ == "__main__":
    main()
