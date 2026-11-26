import os
import hashlib
from healt_data import config


def get_file_sha256(filepath):
    """Menghitung hash SHA-256 dari file untuk akurasi FIM"""
    if not os.path.exists(filepath):
        return None
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


# Simpan baseline hash SHA-256 saat aplikasi pertama kali dijalankan
FIM_BASELINES = {
    path: get_file_sha256(path) for path in config.CONFIG["fim_files"]
}


def init_fim_baselines(fim_files=None):
    """Menginisialisasi ulang baseline SHA-256 sesuai daftar file konfigurasi."""
    global FIM_BASELINES
    files = fim_files if fim_files is not None else config.CONFIG["fim_files"]
    FIM_BASELINES = {
        path: get_file_sha256(path) for path in files
    }
    return FIM_BASELINES


def check_file_integrity():
    """Membandingkan hash SHA-256 saat ini dengan baseline saat startup"""
    modifications = []
    for path, baseline_hash in FIM_BASELINES.items():
        if baseline_hash is None:
            continue
        current_hash = get_file_sha256(path)
        if current_hash and current_hash != baseline_hash:
            modifications.append(path)
    return modifications
