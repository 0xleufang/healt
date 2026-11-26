import os
import sys
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def ensure_dependencies():
    """Otomatis mengecek dan menginstal dependensi yang diperlukan (psutil, rich)."""
    required_packages = ["psutil", "rich"]
    missing = []

    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if not missing:
        return

    if os.environ.get("SYS_SENTINEL_BOOTSTRAPPED") == "1":
        print(f"[!] Gagal mengimpor dependensi setelah instalasi: {', '.join(missing)}")
        sys.exit(1)

    print(f"[*] Dependensi belum lengkap ({', '.join(missing)}). Menginstal otomatis...")

    pip_cmds = [
        [sys.executable, "-m", "pip", "install", *missing],
        [sys.executable, "-m", "pip", "install", "--break-system-packages", *missing],
    ]

    installed = False
    for cmd in pip_cmds:
        try:
            subprocess.check_call(cmd)
            installed = True
            break
        except subprocess.CalledProcessError:
            continue

    if not installed:
        print("[!] Gagal menginstal dependensi otomatis via pip. Silakan instal manual: pip install psutil rich")
        sys.exit(1)

    env = os.environ.copy()
    env["SYS_SENTINEL_BOOTSTRAPPED"] = "1"
    os.execve(sys.executable, [sys.executable, *sys.argv], env)


ensure_dependencies()

from healt_data.cli import entrypoint

if __name__ == "__main__":
    entrypoint()
