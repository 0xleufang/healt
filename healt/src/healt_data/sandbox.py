import ast
import base64
import binascii
import bz2
import datetime
import io
import json
import lzma
import marshal
import math
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import types
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_SANDBOX_IMAGE = "healt-sandbox-base:latest"
DEFAULT_IGNORE_PATHS: List[str] = [
    "tests/",
    "test/",
    "docs/",
    "doc/",
    "examples/",
    "example/",
    "samples/",
    "fixtures/",
    "mock/",
    "mocks/",
    ".git/",
    "__pycache__/",
    "node_modules/",
    "venv/",
    ".venv/",
]

SUSPICIOUS_ENC_EXTS = {
    ".enc",
    ".locked",
    ".crypt",
    ".crypto",
    ".crypted",
    ".ransom",
    ".wnry",
    ".lockbit",
    ".ryk",
    ".encry",
    ".vault",
}

TEXT_SCAN_EXTS = {
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".rb",
    ".pl",
    ".js",
    ".ts",
    ".ps1",
    ".bat",
    ".cmd",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".txt",
    ".md",
    ".rst",
}

SAFE_BINARY_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".zip",
    ".tar",
    ".gz",
    ".xz",
    ".7z",
    ".pyc",
    ".so",
    ".dll",
    ".exe",
    ".bin",
}

ARCHIVE_EXTS = {".zip", ".tar", ".tgz", ".tbz2", ".txz"}

RANSOM_NOTE_NAMES = {
    "readme_to_decrypt.txt",
    "how_to_decrypt.txt",
    "decrypt_instructions.txt",
    "restore_files.txt",
    "ransom_note.txt",
}

DOC_FILE_NAMES = {
    "readme",
    "readme.md",
    "readme.rst",
    "readme.txt",
    "license",
    "license.md",
    "license.txt",
    "contributing.md",
    "security.md",
    "authors",
    "contributors",
    "changelog",
    "changelog.md",
    "changes",
    "changes.rst",
    "history.rst",
}

LOCK_FILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "cargo.lock",
    "poetry.lock",
    "composer.lock",
}

MANIFEST_FILE_NAMES = {
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "gemfile",
    "cargo.toml",
}

TRUE_POSITIVE_RULE_IDS = {
    "EXEC-REVSHELL-001",
    "RES-ANOM-001",
    "BYPASS-EVADE-001",
    "BYPASS-SYMLINK-001",
    "ARCHIVE-RISK-001",
    "MANIFEST-RISK-001",
    "EVADE-005",
    "EVADE-007",
    "DROPPER-001",
    "RANSOM-002",
    "EVADE-004",
    "ANOM-POLY-001",
    "HOOK-001",
    "ANOM-ENC-001",
    "MALWARE-RANSOM-001",
    "MALWARE-EVADE-001",
    "EXEC-HIDDEN-001",
    "EXEC-PIPE-001",
    "EXEC-HOOK-001",
}

DEFAULT_SIGNATURES: List[Dict[str, str]] = [
    {
        "id": "MALWARE-RANSOM-001",
        "category": "malware_ransom",
        "severity": "HIGH",
        "description": "backup/shadow delete command",
        "pattern": r"\b(vssadmin\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled.*no|zfs\s+destroy|btrfs\s+subvolume\s+delete)\b",
    },
    {
        "id": "RANSOM-002",
        "category": "malware_ransom",
        "severity": "HIGH",
        "description": "backup/shadow delete command",
        "pattern": r"\b(vssadmin\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled.*no|zfs\s+destroy|btrfs\s+subvolume\s+delete)\b",
    },
    {
        "id": "MALWARE-EVADE-001",
        "category": "malware_ransom",
        "severity": "HIGH",
        "description": "security defense disable pattern",
        "pattern": r"\b(clickfix|disable_defender|kill_edr|taskkill.*defender|systemctl\s+(stop|disable)\s+(clamav|auditd|wazuh|fail2ban)|setenforce\s+0|ufw\s+disable)\b",
    },
    {
        "id": "EVADE-004",
        "category": "malware_evasion",
        "severity": "HIGH",
        "description": "security defense disable pattern",
        "pattern": r"\b(clickfix|disable_defender|kill_edr|taskkill.*defender|systemctl\s+(stop|disable)\s+(clamav|auditd|wazuh|fail2ban)|setenforce\s+0|ufw\s+disable)\b",
    },
    {
        "id": "EXEC-HIDDEN-001",
        "category": "intentional_exec",
        "severity": "HIGH",
        "description": "decode/unpack + dynamic exec",
        "pattern": r"(b64decode|decompress|fromhex|marshal\.loads)[\s\S]{0,400}(exec|eval|compile)",
    },
    {
        "id": "EVADE-005",
        "category": "intentional_exec",
        "severity": "HIGH",
        "description": "decode/unpack + dynamic exec",
        "pattern": r"(b64decode|decompress|fromhex|marshal\.loads)[\s\S]{0,400}(exec|eval|compile)",
    },
    {
        "id": "EXEC-PIPE-001",
        "category": "intentional_exec",
        "severity": "HIGH",
        "description": "remote script piped to shell",
        "pattern": r"\b(curl|wget|Invoke-WebRequest|iwr)\b[^\n|]*\|\s*(sh|bash|zsh|pwsh|powershell|osascript)\b",
    },
    {
        "id": "DROPPER-001",
        "category": "intentional_exec",
        "severity": "HIGH",
        "description": "remote script piped to shell",
        "pattern": r"\b(curl|wget|Invoke-WebRequest|iwr)\b[^\n|]*\|\s*(sh|bash|zsh|pwsh|powershell|osascript)\b",
    },
    {
        "id": "EXEC-HOOK-001",
        "category": "intentional_exec",
        "severity": "MEDIUM",
        "description": "install/build/preload hook",
        "pattern": r"\b(cmdclass|postinstall|preinstall|DYLD_INSERT_LIBRARIES|LD_PRELOAD)\b",
    },
    {
        "id": "EXEC-PERSIST-001",
        "category": "intentional_exec",
        "severity": "LOW",
        "description": "startup/ssh/cron/service path",
        "pattern": r"(~/\.ssh|/\.ssh|crontab|/etc/cron|systemctl\s+enable|~/\.bashrc|~/\.zshrc|/etc/systemd/system/|/\.config/autostart|LaunchAgents)",
    },
    {
        "id": "DOWNLOAD-OP-001",
        "category": "download_op",
        "severity": "LOW",
        "description": "network download call",
        "pattern": r"\b(curl|wget|Invoke-WebRequest|iwr|urllib\.request\.urlretrieve|requests\.get)\b",
    },
    {
        "id": "SAFE-RUNTIME-001",
        "category": "safe_context",
        "severity": "LOW",
        "description": "standard process/crypto call",
        "pattern": r"\b(subprocess\.(run|Popen|call)|os\.system|zlib\.decompress|base64\.b64decode|Fernet|AES\.new)\b",
    },
]

REVSHELL_PATTERN = re.compile(
    r"("
    r"(/dev/tcp/|/dev/udp/|mkfifo\s+.*nc|nc\s+-[a-zA-Z]*e|ncat\s+-[a-zA-Z]*e|"
    r"bash\s+-i\s+>&?\s*/dev/tcp/|socat\s+.*exec:|"
    r"socket\.socket\([\s\S]{0,250}(connect\(|dup2\(|subprocess|pty\.spawn))"
    r")",
    re.IGNORECASE,
)

RESOURCE_ANOMALY_PATTERN = re.compile(
    r"("
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;|"
    r"while\s+true\s*;\s*do\s+[^;\n]*(?:fork|clone|nohup|dd\s+if=|cat\s+/dev/urandom)|"
    r"\b(xmrig|cpuminer|minerd|stratum\+tcp://|randomx|cryptonight)\b|"
    r"\b(fallocate\s+-l\s+[0-9]+[GM]|dd\s+if=/dev/(zero|urandom)\b)"
    r")",
    re.IGNORECASE,
)

BYPASS_EVASION_PATTERN = re.compile(
    r"("
    r"\b(pickle\.loads|cPickle\.loads|yaml\.unsafe_load)\b|"
    r"(\$\{IFS\}|\$IFS\b|mshta\s+http|rundll32\.exe|certutil\s+-urlcache)"
    r")",
    re.IGNORECASE,
)

_UNSAFE_YAML_LOAD_PATTERN = re.compile(
    r"\byaml\.load\s*\([^)]*(?!SafeLoader|safe_load)[^)]*\)",
    re.IGNORECASE,
)

_MANIFEST_RISK_PATTERN = re.compile(
    r"("
    r"(?:pip\s+install|npm\s+install|yarn\s+add)\s+[^\n]*(?:https?://|git\+|@)[^\n]*(?:sh|bash|curl|wget|eval|exec)|"
    r"(?:\"preinstall\"|\"postinstall\")\s*:\s*\"[^\"]*(?:curl|wget|bash|sh|powershell|node\s+-e|python3?\s+-c)"
    r")",
    re.IGNORECASE,
)

_SUSPICIOUS_PAYLOAD_KEYWORDS = (
    "marshal.loads",
    "exec(",
    "eval(",
    "compile(",
    "__import__",
    "subprocess.",
    "os.system",
    "os.popen",
    "ctypes.",
)

USER_FRIENDLY_ADVICE: Dict[str, str] = {
    "EXEC-REVSHELL-001": "remote shell pattern detected; do not execute on host",
    "EXEC-PIPE-001": "remote download piped directly to shell; inspect URL/script first",
    "DROPPER-001": "remote download piped directly to shell; inspect URL/script first",
    "BYPASS-EVADE-001": "unsafe deserialization or bypass pattern; review matched line",
    "BYPASS-SYMLINK-001": "symlink points outside repository root",
    "RES-ANOM-001": "heavy resource/loop/mining pattern detected",
    "ARCHIVE-RISK-001": "archive ratio or traversal anomaly detected",
    "MANIFEST-RISK-001": "suspicious install/workflow command in manifest",
    "HOOK-001": "git hook can run automatically on git actions",
}

_SHORT_SIG_LABELS: Dict[str, str] = {
    "EXEC-REVSHELL-001": "reverse shell / remote socket",
    "EXEC-PIPE-001": "remote script piped to shell",
    "DROPPER-001": "remote script piped to shell",
    "EXEC-HIDDEN-001": "decode/unpack + dynamic exec",
    "EVADE-005": "decode/unpack + dynamic exec",
    "EVADE-007": "packed/encoded payload",
    "EVADE-006": "unpack/decode call",
    "BYPASS-EVADE-001": "unsafe deserialize / bypass",
    "BYPASS-SYMLINK-001": "symlink escape outside repo",
    "ARCHIVE-RISK-001": "archive ratio / traversal",
    "MANIFEST-RISK-001": "manifest/workflow exec hook",
    "HOOK-001": "git hook auto-exec",
    "ANOM-ENC-001": "encrypted / ransom indicator",
    "ANOM-POLY-001": "polyglot payload in image",
    "ANOM-ENT-001": "high entropy blob",
    "MALWARE-RANSOM-001": "backup/shadow delete cmd",
    "RANSOM-002": "backup/shadow delete cmd",
    "MALWARE-EVADE-001": "security defense disable",
    "EVADE-004": "security defense disable",
    "EXEC-HOOK-001": "install/build/preload hook",
    "EXEC-PERSIST-001": "startup/ssh/cron/service ref",
    "DOWNLOAD-OP-001": "network download call",
    "SAFE-RUNTIME-001": "standard process/crypto call",
}

_HEALT_BANNER = r"""
[0;37m██ ██ ██▀██ ██▀██ ██    ▀██▀[0m
[0;37m██▄██ ██▄   ██▄██ ██     ██ [0m
[0;37m█▓░█▓ █▓░▄▄ █▓░█▓ █▓░▄▄  █▓░[0m
[0;37m▀▀ ▀▀ ▀▀▀▀▀ ▀▀ ▀▀ ▀▀▀▀▀  ▀▀ [0m V.1
"""


def _color(text: str, code: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"\033[{code}m{text}\033[0m"


def _shorten_path(path_str: str, max_len: int = 34) -> str:
    if len(path_str) <= max_len:
        return path_str
    return "..." + path_str[-(max_len - 3) :]


def _find_match_line_and_snippet(content: str, pattern: Optional[re.Pattern]) -> Tuple[int, str]:
    """Mengambil nomor baris dan cuplikan singkat untuk meningkatkan akurasi bukti temuan."""
    if not content:
        return (0, "")
    lines = content.splitlines()
    if pattern is not None:
        for idx, line in enumerate(lines, start=1):
            if pattern.search(line):
                cleaned = re.sub(r"\s+", " ", line.strip())
                return (idx, cleaned[:90])
        m = pattern.search(content)
        if m:
            line_no = content.count("\n", 0, m.start()) + 1
            raw_line = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else m.group(0)
            cleaned = re.sub(r"\s+", " ", raw_line.strip())
            return (line_no, cleaned[:90])
    first_non_empty = next((i for i, l in enumerate(lines, start=1) if l.strip()), 1)
    snippet = re.sub(r"\s+", " ", lines[first_non_empty - 1].strip())[:90] if lines else ""
    return (first_non_empty, snippet)


def _sev_badge(sev: str, bucket: str, is_tp: bool = True) -> str:
    if not is_tp:
        return _color(f"{'CTX':<6}", "2;90" if bucket == "TEST_DOC" else "33")
    s = sev.upper()
    if bucket == "TEST_DOC":
        return _color(f"{s:<6}", "2;90")
    if s == "HIGH":
        return _color(f"{s:<6}", "1;97;41")
    if s == "MEDIUM":
        return _color(f"{s:<6}", "1;30;43")
    return _color(f"{s:<6}", "36")


def _bucket_badge(bucket: str) -> str:
    if bucket == "CORE_RISK":
        return _color("[CORE-RISK]", "1;31")
    if bucket == "TOOL_OP":
        return _color("[TOOL-OP]  ", "36")
    return _color("[TEST/DOC] ", "2;90")


def _shannon_entropy(data: bytes) -> float:
    """Menghitung Shannon entropy (0.0 - 8.0) untuk mendeteksi data terenkripsi/acak."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _has_shebang(fpath: Path) -> bool:
    """Mengecek apakah file diawali shebang (#!)."""
    try:
        with fpath.open("rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def _has_real_shell_payload_in_image(raw_bytes: bytes) -> bool:
    """Cek ketat apakah gambar benar-benar memuat shebang/perintah shell yang terbaca, bukan byte kompresi acak."""
    if not raw_bytes:
        return False
    chunks = [raw_bytes[:256], raw_bytes[-1024:]]
    for chunk in chunks:
        if (
            b"#!/bin/sh" in chunk
            or b"#!/bin/bash" in chunk
            or b"#!/usr/bin/env bash" in chunk
            or b"#!/usr/bin/env python" in chunk
        ):
            return True
        text_part = chunk.decode("utf-8", errors="ignore")
        if re.search(
            r"(curl|wget)\s+[^\n|;&]{1,200}\|\s*(sh|bash|zsh)\b|powershell\s+-enc\b|mshta\s+https?://",
            text_part,
            re.IGNORECASE,
        ):
            return True
    return False


def _inspect_code_obj_names(obj: Any, depth: int = 0) -> List[str]:
    """Menelusuri objek hasil marshal.loads secara aman tanpa mengeksekusinya."""
    if depth > 4 or obj is None:
        return []
    hits: List[str] = []
    if isinstance(obj, types.CodeType):
        names = set(getattr(obj, "co_names", ())) | set(getattr(obj, "co_varnames", ()))
        for name in names:
            if name in {
                "exec",
                "eval",
                "compile",
                "__import__",
                "marshal",
                "loads",
                "subprocess",
                "system",
                "popen",
                "socket",
                "ctypes",
                "urlopen",
                "requests",
            }:
                hits.append(f"bytecode symbol '{name}'")
        for const in getattr(obj, "co_consts", ()):
            hits.extend(_inspect_code_obj_names(const, depth + 1))
    elif isinstance(obj, (tuple, list, set)):
        for item in obj[:30]:
            hits.extend(_inspect_code_obj_names(item, depth + 1))
    return hits


def _unpack_and_inspect_blob(raw: bytes, depth: int = 0) -> Optional[str]:
    """Membongkar lapisan base64/hex/zlib/bz2/lzma/marshal secara aman tanpa exec."""
    if depth > 4 or not raw:
        return None

    text_view = raw.decode("latin1", errors="ignore")
    lower_view = text_view.lower()

    for kw in _SUSPICIOUS_PAYLOAD_KEYWORDS:
        if kw in lower_view:
            return f"decoded payload match '{kw}' (d={depth})"

    for offset in range(0, min(len(raw), 16)):
        try:
            obj = marshal.loads(raw[offset:])
            if isinstance(obj, types.CodeType):
                sym_hits = _inspect_code_obj_names(obj)
                if sym_hits:
                    return f"marshal symbols: {', '.join(sorted(set(sym_hits))[:3])}"
                return f"marshal code object (d={depth} off={offset})"
        except Exception:
            continue

    for _, dec_fn in (
        ("zlib", zlib.decompress),
        ("bz2", bz2.decompress),
        ("lzma", lzma.decompress),
    ):
        try:
            out = dec_fn(raw)
            if out and out != raw:
                nested = _unpack_and_inspect_blob(out, depth + 1)
                if nested:
                    return nested
        except Exception:
            continue

    b64_match = re.search(r"[A-Za-z0-9+/=]{80,}", text_view.strip())
    if b64_match:
        cleaned = re.sub(r"\s+", "", b64_match.group(0))
        padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
        try:
            nxt = base64.b64decode(padded, validate=False)
            if nxt and nxt != raw:
                nested = _unpack_and_inspect_blob(nxt, depth + 1)
                if nested:
                    return nested
        except Exception:
            pass

    return None


def _scan_packed_payloads(content: str) -> List[Tuple[str, str, str, str]]:
    """Membongkar string Base64/Hex yang mengandung payload/code object tersembunyi (TRUE_POSITIVE)."""
    results: List[Tuple[str, str, str, str]] = []

    b64_candidates = re.findall(r"[A-Za-z0-9+/=]{96,}", content)
    for cand in b64_candidates:
        cleaned = re.sub(r"\s+", "", cand)
        padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
        try:
            raw = base64.b64decode(padded, validate=False)
        except Exception:
            continue
        if len(raw) >= 24:
            unpacked_reason = _unpack_and_inspect_blob(raw, depth=1)
            if unpacked_reason:
                results.append(("TRUE_POSITIVE", "HIGH", "EVADE-007", unpacked_reason))

    hex_candidates = re.findall(r"\b[0-9a-fA-F]{160,}\b", content)
    for hcand in hex_candidates:
        cleaned_hex = re.sub(r"\s+", "", hcand)
        if len(cleaned_hex) % 2 == 0:
            try:
                raw_hex = binascii.unhexlify(cleaned_hex)
                unpacked_reason = _unpack_and_inspect_blob(raw_hex, depth=1)
                if unpacked_reason:
                    results.append(("TRUE_POSITIVE", "HIGH", "EVADE-007", f"hex {unpacked_reason}"))
            except Exception:
                continue

    return results


def _scan_ast_evasion(content: str) -> List[Tuple[str, str, str, str]]:
    """Mendeteksi kombinasi decode+exec (TRUE_POSITIVE) vs pemanggilan normal (CONTEXTUAL)."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    findings: List[Tuple[str, str, str, str]] = []
    has_exec_like = False
    has_decode_like = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval", "compile"}:
                has_exec_like = True
            elif isinstance(node.func, ast.Attribute) and node.func.attr in {"loads", "decompress"}:
                owner_name = ""
                if isinstance(node.func.value, ast.Name):
                    owner_name = node.func.value.id.lower()
                elif isinstance(node.func.value, ast.Attribute):
                    owner_name = node.func.value.attr.lower()
                if owner_name in {"marshal", "zlib", "bz2", "lzma"}:
                    has_decode_like = True
                    findings.append(("CONTEXTUAL", "LOW", "EVADE-006", f"{owner_name}.{node.func.attr}()"))
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "b64decode":
                has_decode_like = True

        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) >= 96:
            cleaned = re.sub(r"\s+", "", node.value)
            if re.fullmatch(r"[A-Za-z0-9+/=]+", cleaned):
                padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
                try:
                    raw = base64.b64decode(padded, validate=False)
                    reason = _unpack_and_inspect_blob(raw, depth=1)
                    if reason:
                        findings.append(("TRUE_POSITIVE", "HIGH", "EVADE-007", f"ast {reason}"))
                except Exception:
                    pass

    if has_exec_like and has_decode_like:
        findings.append(("TRUE_POSITIVE", "HIGH", "EVADE-005", "decode/unpack + exec/eval/compile"))

    return findings


def _scan_symlink_escapes(workspace_dir: Path, ignore_paths: List[str]) -> List[Dict[str, Any]]:
    """Mendeteksi symlink di dalam workspace yang mengarah keluar batas direktori kerja (TP)."""
    results: List[Dict[str, Any]] = []
    root_resolved = workspace_dir.resolve()
    for root, dirs, files in os.walk(workspace_dir, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        entries = list(dirs) + list(files)
        for name in entries:
            p = Path(root) / name
            if not p.is_symlink():
                continue
            try:
                rel_path_str = str(p.relative_to(workspace_dir)).replace("\\", "/")
            except ValueError:
                rel_path_str = str(p).replace("\\", "/")
            in_ignored = is_ignored_path(rel_path_str, ignore_paths)
            try:
                target_link = os.readlink(p)
                target_resolved = p.resolve(strict=False)
                escapes = root_resolved not in target_resolved.parents and target_resolved != root_resolved
            except OSError:
                target_link = "<unreadable>"
                escapes = True
            if escapes:
                results.append(
                    {
                        "bucket": "TEST_DOC" if in_ignored else "CORE_RISK",
                        "severity": "HIGH",
                        "rule_id": "BYPASS-SYMLINK-001",
                        "category": "bypass_escape",
                        "description": "symlink escape outside repo",
                        "path": rel_path_str,
                        "evidence": "TRUE_POSITIVE",
                        "line": 1,
                        "snippet": f"->{target_link}"[:75],
                    }
                )
    return results


def _inspect_archive_file(fpath: Path, rel_path_str: str, in_ignored: bool) -> Optional[Dict[str, Any]]:
    """Memeriksa arsip (.zip/.tar.*) secara aman untuk mendeteksi zip bomb, symlink escape, atau traversal."""
    try:
        comp_size = fpath.stat().st_size
    except OSError:
        return None
    if comp_size <= 0 or comp_size > 50_000_000:
        return None

    fname_lower = fpath.name.lower()
    total_uncompressed = 0
    entry_count = 0
    max_entries = 2500
    max_uncompressed_bytes = 250 * 1024 * 1024

    try:
        if fname_lower.endswith(".zip"):
            with zipfile.ZipFile(fpath, "r") as zf:
                for info in zf.infolist()[:max_entries]:
                    entry_count += 1
                    total_uncompressed += max(0, info.file_size)
                    norm_name = info.filename.replace("\\", "/")
                    if norm_name.startswith("/") or ".." in Path(norm_name).parts:
                        return {
                            "bucket": "TEST_DOC" if in_ignored else "CORE_RISK",
                            "severity": "HIGH",
                            "rule_id": "ARCHIVE-RISK-001",
                            "category": "archive_anomaly",
                            "description": "zip path traversal entry",
                            "path": rel_path_str,
                            "evidence": "TRUE_POSITIVE",
                            "line": 1,
                            "snippet": norm_name[:75],
                        }
                    if info.file_size > 100 * 1024 * 1024 or (
                        info.compress_size > 0
                        and (info.file_size / info.compress_size) > 100.0
                        and info.file_size > 5 * 1024 * 1024
                    ):
                        return {
                            "bucket": "TEST_DOC" if in_ignored else "CORE_RISK",
                            "severity": "HIGH",
                            "rule_id": "ARCHIVE-RISK-001",
                            "category": "archive_anomaly",
                            "description": "zip compression ratio anomaly",
                            "path": rel_path_str,
                            "evidence": "TRUE_POSITIVE",
                            "line": 1,
                            "snippet": f"ratio~{info.file_size // max(info.compress_size, 1)}:1",
                        }
        elif fname_lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
            with tarfile.open(fpath, "r:*") as tf:
                for member in tf.getmembers()[:max_entries]:
                    entry_count += 1
                    total_uncompressed += max(0, member.size)
                    norm_name = member.name.replace("\\", "/")
                    if norm_name.startswith("/") or ".." in Path(norm_name).parts:
                        return {
                            "bucket": "TEST_DOC" if in_ignored else "CORE_RISK",
                            "severity": "HIGH",
                            "rule_id": "ARCHIVE-RISK-001",
                            "category": "archive_anomaly",
                            "description": "tar path traversal entry",
                            "path": rel_path_str,
                            "evidence": "TRUE_POSITIVE",
                            "line": 1,
                            "snippet": norm_name[:75],
                        }
                    if member.issym() or member.islnk():
                        link_target = (member.linkname or "").replace("\\", "/")
                        if link_target.startswith("/") or ".." in Path(link_target).parts:
                            return {
                                "bucket": "TEST_DOC" if in_ignored else "CORE_RISK",
                                "severity": "HIGH",
                                "rule_id": "ARCHIVE-RISK-001",
                                "category": "archive_anomaly",
                                "description": "tar link escape entry",
                                "path": rel_path_str,
                                "evidence": "TRUE_POSITIVE",
                                "line": 1,
                                "snippet": f"->{link_target[:70]}",
                            }
    except Exception:
        return None

    if total_uncompressed > max_uncompressed_bytes or (
        comp_size > 0 and (total_uncompressed / comp_size) > 120.0 and total_uncompressed > 10 * 1024 * 1024
    ):
        return {
            "bucket": "TEST_DOC" if in_ignored else "CORE_RISK",
            "severity": "HIGH",
            "rule_id": "ARCHIVE-RISK-001",
            "category": "archive_anomaly",
            "description": "archive bomb / oversized extract",
            "path": rel_path_str,
            "evidence": "TRUE_POSITIVE",
            "line": 1,
            "snippet": f"raw={total_uncompressed}B n={entry_count}",
        }
    return None


def monitor_runtime_resources(
    duration_sec: float = 2.0,
    sample_interval: float = 0.25,
    cpu_spike_threshold: float = 85.0,
    mem_spike_mb_threshold: float = 768.0,
) -> Dict[str, Any]:
    """Memantau lonjakan CPU, memori RSS, dan jumlah proses/thread saat runtime secara ringan."""
    samples: List[Dict[str, Any]] = []
    anomalies: List[str] = []
    start_ts = time.monotonic()

    try:
        import psutil  # type: ignore
    except ImportError:
        return {
            "available": False,
            "samples": [],
            "anomalies": [],
            "peak_cpu_pct": 0.0,
            "peak_rss_mb": 0.0,
            "peak_pids": 0,
        }

    psutil.cpu_percent(interval=None)
    peak_cpu = 0.0
    peak_rss_mb = 0.0
    peak_pids = 0

    while (time.monotonic() - start_ts) < duration_sec:
        cpu_pct = float(psutil.cpu_percent(interval=None))
        vm = psutil.virtual_memory()
        used_mb = round((vm.total - vm.available) / (1024 * 1024), 1)
        pid_count = len(psutil.pids())

        peak_cpu = max(peak_cpu, cpu_pct)
        peak_rss_mb = max(peak_rss_mb, used_mb)
        peak_pids = max(peak_pids, pid_count)

        samples.append(
            {
                "cpu_pct": cpu_pct,
                "mem_used_mb": used_mb,
                "pids": pid_count,
            }
        )

        if cpu_pct >= cpu_spike_threshold:
            anomalies.append(f"cpu spike {cpu_pct:.1f}%")
        if used_mb >= mem_spike_mb_threshold and vm.percent >= 85.0:
            anomalies.append(f"mem pressure {vm.percent:.1f}%")

        time.sleep(max(0.05, sample_interval))

    return {
        "available": True,
        "samples": samples,
        "anomalies": sorted(set(anomalies)),
        "peak_cpu_pct": round(peak_cpu, 1),
        "peak_rss_mb": peak_rss_mb,
        "peak_pids": peak_pids,
    }


def record_scan_history(
    target_label: str,
    rate_info: Dict[str, Any],
    findings: List[Dict[str, Any]],
    history_path: Optional[Path] = None,
) -> Path:
    """Menyimpan ringkasan hasil pindai ke JSONL untuk transparansi dan audit lokal."""
    log_file = history_path or (Path.home() / ".healt" / "scan_history.jsonl")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": target_label,
        "score": rate_info.get("score", 0),
        "verdict": rate_info.get("verdict", "UNKNOWN"),
        "tp_count": rate_info.get("tp_count", 0),
        "ctx_count": rate_info.get("ctx_count", 0),
        "rules_triggered": sorted({f.get("rule_id", "") for f in findings if f.get("rule_id")}),
    }
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return log_file


def _has_bypass_evasion(content: str, ext: str) -> bool:
    """Mendeteksi bypass/deserialisasi berbahaya dengan memfilter $IFS biasa di skrip shell."""
    if _UNSAFE_YAML_LOAD_PATTERN.search(content):
        return True
    if re.search(
        r"\b(pickle\.loads|cPickle\.loads|yaml\.unsafe_load|mshta\s+http|rundll32\.exe|certutil\s+-urlcache)\b",
        content,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"(\$\{IFS\}|\$IFS\b)", content):
        if ext in {".sh", ".bash", ".zsh"} and not re.search(
            r"\b(curl|wget|nc|ncat|socat|python3?|perl|ruby|sh|bash)\b[^\n;]*(\$\{IFS\}|\$IFS\b)",
            content,
            re.IGNORECASE,
        ):
            return False
        return True
    return False


def _classify_evidence(rule_id: str, severity: str, is_doc_file: bool) -> Tuple[str, str]:
    """Membedakan temuan TRUE_POSITIVE nyata vs CONTEXTUAL (konteks wajar / FP potensial)."""
    if is_doc_file:
        return ("CONTEXTUAL", "LOW")
    if rule_id in TRUE_POSITIVE_RULE_IDS:
        return ("TRUE_POSITIVE", severity)
    return ("CONTEXTUAL", "LOW" if severity == "MEDIUM" else severity)


def calculate_security_rate(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Menghitung security rate (0-100%) dengan fokus pada ancaman nyata (TRUE_POSITIVE)."""
    core_risk = [f for f in findings if f["bucket"] == "CORE_RISK"]
    tool_op = [f for f in findings if f["bucket"] == "TOOL_OP"]
    test_doc = [f for f in findings if f["bucket"] == "TEST_DOC"]

    tp_hits = [f for f in core_risk if f.get("evidence") == "TRUE_POSITIVE"]
    ctx_hits = [f for f in core_risk if f.get("evidence") != "TRUE_POSITIVE"]

    high_n = sum(1 for f in core_risk if f.get("evidence") == "TRUE_POSITIVE" and f["severity"] == "HIGH")
    med_n = sum(1 for f in core_risk if f.get("evidence") == "TRUE_POSITIVE" and f["severity"] == "MEDIUM")
    low_n = sum(1 for f in core_risk if f.get("evidence") != "TRUE_POSITIVE" or f["severity"] == "LOW")

    penalty = 0
    for f in tp_hits:
        penalty += 50 if f["severity"] == "HIGH" else 25

    ctx_penalty = min(len(ctx_hits) * 2, 20)
    penalty += ctx_penalty

    score = max(0, min(100, 100 - penalty))

    if len(tp_hits) > 0:
        verdict = "BLOCKED"
        verdict_label = "BLOCKED"
        allowed = False
    elif score < 85:
        verdict = "CAUTION"
        verdict_label = "CAUTION"
        allowed = True
    else:
        verdict = "SAFE"
        verdict_label = "SAFE"
        allowed = True

    return {
        "score": score,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "allowed": allowed,
        "core_count": len(core_risk),
        "tp_count": len(tp_hits),
        "ctx_count": len(ctx_hits),
        "high_count": high_n,
        "medium_count": med_n,
        "low_count": low_n,
        "tool_op_count": len(tool_op),
        "test_doc_count": len(test_doc),
    }


def get_project_root() -> Path:
    """Mengembalikan root folder proyek healt (src/healt_data/sandbox.py -> ../..)."""
    return Path(__file__).resolve().parents[2]


def resolve_default_dest(explicit_dest: Optional[str] = None) -> Path:
    """Menentukan folder tujuan peletakan repo yang rapi dan menghindari mengotori folder healt."""
    if explicit_dest:
        return Path(explicit_dest).expanduser().resolve()
    cwd = Path.cwd().resolve()
    project_root = get_project_root().resolve()
    if cwd == project_root or project_root in cwd.parents:
        fallback = Path.home() / "healt-workspace"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback
    return cwd


def load_signature_rules(rules_path: Optional[Path] = None) -> Dict[str, Any]:
    """Memuat aturan signature dan ignore_paths dari rules/signatures.json."""
    target = rules_path or (get_project_root() / "rules" / "signatures.json")
    if not target.exists():
        return {"ignore_paths": DEFAULT_IGNORE_PATHS, "signatures": DEFAULT_SIGNATURES}
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        sigs = data.get("signatures")
        ignores = data.get("ignore_paths")
        merged_ignores = list(DEFAULT_IGNORE_PATHS)
        if isinstance(ignores, list):
            for p in ignores:
                clean = str(p).lstrip("./").strip("/")
                if clean and f"{clean}/" not in merged_ignores:
                    merged_ignores.append(f"{clean}/")
        return {
            "ignore_paths": merged_ignores,
            "signatures": sigs if isinstance(sigs, list) and sigs else DEFAULT_SIGNATURES,
        }
    except (OSError, json.JSONDecodeError) as exc:
        print(_color(f"[WRN] bad signatures.json ({exc}); using built-in rules", "33"))
        return {"ignore_paths": DEFAULT_IGNORE_PATHS, "signatures": DEFAULT_SIGNATURES}


def is_ignored_path(rel_path_str: str, ignore_paths: List[str]) -> bool:
    """Mengecek apakah path berada di folder pengecualian umum seperti tests/ atau docs/."""
    normalized = rel_path_str.replace("\\", "/").lstrip("./")
    parts = normalized.split("/")
    for prefix in ignore_paths:
        clean_prefix = prefix.strip("/").replace("\\", "/")
        if not clean_prefix:
            continue
        if normalized == clean_prefix or normalized.startswith(f"{clean_prefix}/") or clean_prefix in parts[:-1]:
            return True
    return False


def normalize_repo_url(raw_url: str) -> str:
    """Menormalkan input 'github.com/user/repo' menjadi 'https://github.com/user/repo.git'."""
    cleaned = raw_url.strip()
    if cleaned.startswith(("https://", "http://", "git@", "ssh://")):
        return cleaned
    if cleaned.startswith(("github.com/", "gitlab.com/", "bitbucket.org/")):
        url = f"https://{cleaned}"
        return url if url.endswith(".git") else f"{url}.git"
    return cleaned


def detect_engine(preferred: str = "auto") -> Optional[str]:
    """Mendeteksi engine container yang tersedia (podman atau docker), atau None jika belum terpasang."""
    if preferred != "auto":
        if shutil.which(preferred):
            return preferred
        raise RuntimeError(f"Engine '{preferred}' not found in PATH.")
    for candidate in ("podman", "docker"):
        if shutil.which(candidate):
            return candidate
    return None


def sanitize_repo_name(repo_url: str) -> str:
    """Mengambil nama folder repo yang aman dari URL Git."""
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name or "sandbox_repo"


def ensure_sandbox_image(engine: str, base_image: str, sandbox_image: str = DEFAULT_SANDBOX_IMAGE) -> str:
    """Memastikan image sandbox memiliki git & ca-certificates terinstal."""
    check = subprocess.run(
        [engine, "image", "exists", sandbox_image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if check.returncode == 0:
        return sandbox_image
    print(_color(f"[INF] Building sandbox image {sandbox_image} from {base_image}", "36"))
    build_ctx = Path(f"/tmp/healt_sandbox_ctx_{os.getpid()}")
    build_ctx.mkdir(parents=True, exist_ok=True)
    dockerfile = build_ctx / "Dockerfile"
    dockerfile.write_text(
        f"FROM {base_image}\n"
        "RUN if command -v apt-get >/dev/null 2>&1; then "
        "apt-get update -qq && apt-get install -y -qq --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*; "
        "elif command -v apk >/dev/null 2>&1; then "
        "apk add --no-cache -q git ca-certificates; "
        "fi\n"
        "RUN mkdir -p /tmp/sandbox && chmod 1777 /tmp/sandbox\n",
        encoding="utf-8",
    )
    try:
        subprocess.run(
            [engine, "build", "-t", sandbox_image, "-f", str(dockerfile), str(build_ctx)],
            check=True,
        )
        return sandbox_image
    except subprocess.CalledProcessError:
        print(_color("[WRN] Custom sandbox image build failed; fallback to base image", "33"))
        return base_image
    finally:
        shutil.rmtree(build_ctx, ignore_errors=True)


def build_hardened_base_cmd(
    engine: str,
    image: str,
    container_name: str,
    memory: str,
    cpus: str,
    pids_limit: int,
    network_mode: Optional[str] = None,
    interactive: bool = False,
) -> List[str]:
    """Menyusun argumen dasar container dengan hardening."""
    cmd = [
        engine,
        "run",
        "--rm",
        "--name",
        container_name,
        "--user",
        "1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--memory={memory}",
        f"--cpus={cpus}",
        f"--pids-limit={pids_limit}",
        "-w",
        "/tmp",
    ]
    if interactive:
        cmd.append("-it")
    if network_mode:
        cmd.extend(["--network", network_mode])
    cmd.append(image)
    return cmd


def run_cmd(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True)


def scan_workspace_structured(workspace_dir: Path, rules_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Memindai file demi file di lokasi mana pun, memisahkan ancaman nyata (TP) vs konteks (CTX)."""
    rules_cfg = load_signature_rules(rules_path)
    ignore_paths: List[str] = rules_cfg["ignore_paths"]
    raw_sigs: List[Dict[str, str]] = rules_cfg["signatures"]
    compiled_rules = []
    for sig in raw_sigs:
        pat = sig.get("pattern", "")
        if not pat:
            continue
        try:
            regex = re.compile(pat)
        except re.error:
            continue
        compiled_rules.append(
            {
                "id": sig.get("id", "RULE"),
                "category": sig.get("category", "general"),
                "severity": sig.get("severity", "LOW").upper(),
                "description": sig.get("description", pat),
                "regex": regex,
            }
        )
    findings: List[Dict[str, Any]] = []
    seen_keys = set()

    def add_finding(
        bucket: str,
        severity: str,
        rule_id: str,
        category: str,
        description: str,
        path_str: str,
        evidence: str = "CONTEXTUAL",
        line: int = 0,
        snippet: str = "",
    ) -> None:
        key = (bucket, evidence, severity, rule_id, description, path_str, line)
        if key not in seen_keys:
            seen_keys.add(key)
            findings.append(
                {
                    "bucket": bucket,
                    "severity": severity,
                    "rule_id": rule_id,
                    "category": category,
                    "description": description,
                    "path": path_str,
                    "evidence": evidence,
                    "line": line,
                    "snippet": snippet,
                    "advice": USER_FRIENDLY_ADVICE.get(rule_id, ""),
                }
            )

    for sym_item in _scan_symlink_escapes(workspace_dir, ignore_paths):
        add_finding(
            sym_item["bucket"],
            sym_item["severity"],
            sym_item["rule_id"],
            sym_item["category"],
            sym_item["description"],
            sym_item["path"],
            sym_item["evidence"],
            line=sym_item.get("line", 1),
            snippet=sym_item.get("snippet", ""),
        )

    for root, dirs, files in os.walk(workspace_dir):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.is_symlink():
                continue
            try:
                rel_path_str = str(fpath.relative_to(workspace_dir)).replace("\\", "/")
            except ValueError:
                rel_path_str = str(fpath).replace("\\", "/")
            in_ignored = is_ignored_path(rel_path_str, ignore_paths)
            ext = fpath.suffix.lower()
            fname_lower = fname.lower()
            is_changelog = fname_lower.startswith(("changes", "changelog", "history"))
            is_doc_file = ext in {".md", ".rst", ".txt"} or is_changelog or fname_lower in DOC_FILE_NAMES
            is_lock_file = fname_lower in LOCK_FILE_NAMES
            is_manifest_file = fname_lower in MANIFEST_FILE_NAMES or ".github/workflows/" in rel_path_str
            is_dockerfile = fname_lower in {"dockerfile"} or fname_lower.startswith("dockerfile.")
            is_husky_hook = ".husky/" in rel_path_str
            default_bucket = "TEST_DOC" if (in_ignored or is_doc_file) else "CORE_RISK"

            if fname in {"pre-commit", "post-checkout", "post-merge", "pre-push"}:
                hook_ev, hook_sev = ("CONTEXTUAL", "LOW") if is_husky_hook else ("TRUE_POSITIVE", "HIGH")
                add_finding(
                    "TOOL_OP" if is_husky_hook else default_bucket,
                    hook_sev,
                    "HOOK-001",
                    "intentional_exec",
                    "git hook auto-exec",
                    rel_path_str,
                    hook_ev,
                    line=1,
                    snippet=fname,
                )
            if ext in SUSPICIOUS_ENC_EXTS or fname_lower in RANSOM_NOTE_NAMES:
                add_finding(
                    default_bucket,
                    "HIGH",
                    "ANOM-ENC-001",
                    "malware_ransom",
                    f"encrypted/ransom file ({ext or fname_lower})",
                    rel_path_str,
                    "TRUE_POSITIVE",
                    line=1,
                    snippet=fname,
                )

            if ext in ARCHIVE_EXTS or fname_lower.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
                arc_hit = _inspect_archive_file(fpath, rel_path_str, in_ignored)
                if arc_hit:
                    add_finding(
                        arc_hit["bucket"],
                        arc_hit["severity"],
                        arc_hit["rule_id"],
                        arc_hit["category"],
                        arc_hit["description"],
                        arc_hit["path"],
                        arc_hit["evidence"],
                        line=arc_hit.get("line", 1),
                        snippet=arc_hit.get("snippet", ""),
                    )

            try:
                size = fpath.stat().st_size
            except OSError:
                continue
            if size == 0 or size > 4_000_000:
                continue

            raw_bytes: Optional[bytes] = None
            if ext not in SAFE_BINARY_EXTS:
                try:
                    raw_bytes = fpath.read_bytes()
                    ent = _shannon_entropy(raw_bytes)
                    if ent >= 7.85 and len(raw_bytes) >= 2048:
                        add_finding(
                            default_bucket,
                            "LOW",
                            "ANOM-ENT-001",
                            "high_entropy",
                            f"entropy {ent:.2f}/8.0",
                            rel_path_str,
                            "CONTEXTUAL",
                            line=1,
                            snippet=f"{len(raw_bytes)}B",
                        )
                except OSError:
                    raw_bytes = None

            if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
                try:
                    sample_bytes = raw_bytes if raw_bytes is not None else fpath.read_bytes()
                    if _has_real_shell_payload_in_image(sample_bytes):
                        add_finding(
                            default_bucket,
                            "HIGH",
                            "ANOM-POLY-001",
                            "intentional_exec",
                            "polyglot payload in image",
                            rel_path_str,
                            "TRUE_POSITIVE",
                            line=1,
                            snippet="shell/script signature in image",
                        )
                except OSError:
                    pass

            is_build_or_docker = fname in {"Makefile", "makefile", "GNUmakefile", "Dockerfile"} or is_dockerfile
            if ext not in TEXT_SCAN_EXTS and not is_build_or_docker and not _has_shebang(fpath):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            if not is_doc_file and not is_lock_file:
                if REVSHELL_PATTERN.search(content):
                    ln, snip = _find_match_line_and_snippet(content, REVSHELL_PATTERN)
                    add_finding(
                        "CORE_RISK",
                        "HIGH",
                        "EXEC-REVSHELL-001",
                        "intentional_exec",
                        "reverse shell / remote socket",
                        rel_path_str,
                        "TRUE_POSITIVE",
                        line=ln,
                        snippet=snip,
                    )

                if RESOURCE_ANOMALY_PATTERN.search(content) and not in_ignored:
                    ln, snip = _find_match_line_and_snippet(content, RESOURCE_ANOMALY_PATTERN)
                    add_finding(
                        default_bucket,
                        "HIGH",
                        "RES-ANOM-001",
                        "resource_anomaly",
                        "resource / miner / fork anomaly",
                        rel_path_str,
                        "TRUE_POSITIVE",
                        line=ln,
                        snippet=snip,
                    )

                if _has_bypass_evasion(content, ext):
                    ev_pat = (
                        _UNSAFE_YAML_LOAD_PATTERN
                        if _UNSAFE_YAML_LOAD_PATTERN.search(content)
                        else BYPASS_EVASION_PATTERN
                    )
                    ln, snip = _find_match_line_and_snippet(content, ev_pat)
                    add_finding(
                        default_bucket,
                        "HIGH",
                        "BYPASS-EVADE-001",
                        "bypass_evasion",
                        "unsafe deserialize / bypass",
                        rel_path_str,
                        "TRUE_POSITIVE",
                        line=ln,
                        snippet=snip,
                    )

                if is_manifest_file and _MANIFEST_RISK_PATTERN.search(content):
                    ln, snip = _find_match_line_and_snippet(content, _MANIFEST_RISK_PATTERN)
                    add_finding(
                        default_bucket,
                        "HIGH",
                        "MANIFEST-RISK-001",
                        "supply_chain",
                        "manifest/workflow exec hook",
                        rel_path_str,
                        "TRUE_POSITIVE",
                        line=ln,
                        snippet=snip,
                    )

            if not is_doc_file and not is_lock_file and (ext == ".py" or _has_shebang(fpath)):
                for ev_type, sev, rid, desc in _scan_ast_evasion(content):
                    ln, snip = _find_match_line_and_snippet(content, None)
                    add_finding(
                        default_bucket, sev, rid, "intentional_exec", desc, rel_path_str, ev_type, line=ln, snippet=snip
                    )

            if not is_doc_file and not is_lock_file:
                for ev_type, sev, rid, desc in _scan_packed_payloads(content):
                    ln, snip = _find_match_line_and_snippet(content, None)
                    add_finding(
                        default_bucket, sev, rid, "intentional_exec", desc, rel_path_str, ev_type, line=ln, snippet=snip
                    )

            for rule in compiled_rules:
                if is_changelog and rule["id"] == "TOOL-EXEC-001":
                    continue
                if is_lock_file and rule["id"] in {"EXEC-HOOK-001", "EXEC-HIDDEN-001", "EVADE-005"}:
                    continue
                if rule["regex"].search(content):
                    ln, snip = _find_match_line_and_snippet(content, rule["regex"])
                    ev_type, sev = _classify_evidence(rule["id"], rule["severity"], is_doc_file)
                    if is_dockerfile and rule["id"] in {
                        "RANSOM-002",
                        "MALWARE-RANSOM-001",
                        "DROPPER-001",
                        "EXEC-PIPE-001",
                        "DOWNLOAD-OP-001",
                        "EXEC-HOOK-001",
                    }:
                        ev_type, sev = ("CONTEXTUAL", "LOW")
                    if is_doc_file or in_ignored:
                        bucket = "TEST_DOC"
                        ev_type, sev = ("CONTEXTUAL", "LOW")
                    elif sev == "LOW" or rule["category"] in {"tool_runtime", "download_op", "safe_context"}:
                        bucket = "TOOL_OP"
                    else:
                        bucket = "CORE_RISK"
                    add_finding(
                        bucket,
                        sev,
                        rule["id"],
                        rule["category"],
                        rule["description"],
                        rel_path_str,
                        ev_type,
                        line=ln,
                        snippet=snip,
                    )

    bucket_order = {"CORE_RISK": 0, "TOOL_OP": 1, "TEST_DOC": 2}
    ev_order = {"TRUE_POSITIVE": 0, "CONTEXTUAL": 1}
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(
        key=lambda f: (
            bucket_order.get(f["bucket"], 9),
            ev_order.get(f.get("evidence", "CONTEXTUAL"), 9),
            sev_order.get(f["severity"], 9),
            f["rule_id"],
            f["path"],
            f.get("line", 0),
        )
    )
    return findings


def _concise_reason(item: Dict[str, Any]) -> str:
    rid = item.get("rule_id", "")
    snip = (item.get("snippet") or "").strip()
    base = _SHORT_SIG_LABELS.get(rid) or (item.get("description") or "").strip()
    if snip and item.get("evidence") == "TRUE_POSITIVE":
        clean_snip = re.sub(r"\s+", " ", snip)[:42]
        return f"{base} [{clean_snip}]"
    return base


def _format_siem_finding_line(item: Dict[str, Any]) -> str:
    is_tp = item.get("evidence") == "TRUE_POSITIVE"
    bucket = item.get("bucket", "CORE_RISK")
    sev = (item.get("severity") or "LOW").upper()
    rid = item.get("rule_id", "RULE")
    line_no = item.get("line", 0)

    ev_tag = _color("TP ", "1;97;41") if is_tp else _color("CTX", "2;90" if bucket == "TEST_DOC" else "33")
    b_tag = _bucket_badge(bucket)
    s_tag = _sev_badge(sev, bucket, is_tp=is_tp)
    rid_col = _color(f"{rid:<18}", "1;37" if is_tp else ("36" if bucket == "TOOL_OP" else "2;90"))

    loc = f"{item.get('path', '')}:{line_no}" if line_no else str(item.get("path", ""))
    loc_short = _shorten_path(loc, 34)
    loc_col = _color(f"{loc_short:<34}", "1;37" if is_tp else ("36" if bucket == "TOOL_OP" else "2;90"))

    reason = _concise_reason(item)
    reason_col = _color(reason, "1;37" if is_tp else ("37" if bucket == "TOOL_OP" else "2;90"))
    return f"  {b_tag} {ev_tag} {s_tag} {rid_col} {loc_col} {reason_col}"


def scan_workspace_for_red_flags(workspace_dir: Path, rules_path: Optional[Path] = None) -> List[str]:
    """Mengembalikan daftar baris temuan signature ringkas."""
    structured = scan_workspace_structured(workspace_dir, rules_path)
    return [_format_siem_finding_line(item) for item in structured]


def print_siem_banner(engine: Optional[str], repo_url: str, target_dest: Path) -> None:
    """Header bergaya CLI security tool: simpel, tajam, tanpa kotak berlebih."""
    eng_label = engine or "static-only"
    eng_col = _color(eng_label, "1;36") if engine else _color(eng_label, "33")
    print(_color(_HEALT_BANNER.rstrip("\n"), "1;36"))
    print(f"                                       ")
    print(f"                  {_color('by leu_fang', '37')}  {_color('repo & sandbox guard', '2;37')}")
    print(f"                                         ")
    print(f"{_color('[INF]', '36')} target : {_color(repo_url, '1;37')}")
    print(f"{_color('[INF]', '36')} engine : {eng_col}   dest : {_color(_shorten_path(str(target_dest), 38), '36')}")


def print_siem_scan_report(findings: List[Dict[str, Any]], rate_info: Dict[str, Any]) -> None:
    """Menampilkan hasil signature scan ala CLI security tool."""
    score = rate_info["score"]
    verdict = rate_info["verdict"]
    verdict_label = rate_info["verdict_label"]
    if verdict == "BLOCKED":
        rate_col = _color(f"{score}%", "1;97;41")
        status_col = _color(verdict_label, "1;97;41")
    elif verdict == "CAUTION":
        rate_col = _color(f"{score}%", "1;30;43")
        status_col = _color(verdict_label, "1;30;43")
    else:
        rate_col = _color(f"{score}%", "1;30;42")
        status_col = _color(verdict_label, "1;32")
    print(
        f"{_color('[INF]', '36')} status : [{status_col}]  rate={rate_col}  "
        f"TP={_color(str(rate_info['tp_count']), '1;31')}  "
        f"CTX={_color(str(rate_info['ctx_count']), '33')}  "
        f"TOOL={_color(str(rate_info['tool_op_count']), '36')}  "
        f"DOC={_color(str(rate_info['test_doc_count']), '2;90')}"
    )
    if not findings:
        print(f"{_color('[INF]', '32')} clean  : no signature hits")
        return
    print(_color("  " + "-" * 88, "2;90"))
    print(
        _color(
            f"  {'BUCKET':<11} {'EV ':3} {'SEV':<6} {'SIGNATURE':<18} {'FILE:LINE':<34} MATCH",
            "2;37",
        )
    )
    print(_color("  " + "-" * 88, "2;90"))
    core_risk = [f for f in findings if f["bucket"] == "CORE_RISK"]
    tool_op = [f for f in findings if f["bucket"] == "TOOL_OP"]
    test_doc = [f for f in findings if f["bucket"] == "TEST_DOC"]
    for group, limit in ((core_risk, 12), (tool_op, 5), (test_doc, 3)):
        for item in group[:limit]:
            print(_format_siem_finding_line(item))
        sisa = len(group) - min(len(group), limit)
        if sisa > 0:
            print(_color(f"    +{sisa} more in {group[0]['bucket']}", "2;90"))
    print(_color("  " + "-" * 88, "2;90"))


def promote_to_host(source_dir: Path, dest_parent: Path, repo_name: str, force: bool = False) -> Path:
    """Menyalin repo langsung ke folder tujuan aktif di sistem host tanpa subfolder tambahan."""
    dest_parent.mkdir(parents=True, exist_ok=True)
    target_path = dest_parent / repo_name
    if target_path.exists():
        if not force:
            raise FileExistsError(f"target exists: {target_path} (use --force)")
        shutil.rmtree(target_path)
    shutil.copytree(source_dir, target_path, ignore=shutil.ignore_patterns(".git"))
    return target_path


def run_sandbox_workflow(
    raw_repo_url: str,
    engine_pref: str = "auto",
    image: str = "python:3.12-slim",
    install_cmd: str = "",
    test_cmd: str = "",
    shell: bool = False,
    dest: Optional[str] = None,
    force: bool = False,
    memory: str = "1g",
    cpus: str = "1.0",
    pids_limit: int = 128,
) -> int:
    """Menjalankan static scan + gate keamanan + sandbox container (jika tersedia) + konfirmasi peletakan."""
    repo_url = normalize_repo_url(raw_repo_url)
    target_dest = resolve_default_dest(dest)
    temp_extract_dir = Path(f"/tmp/healt_sandbox_extract_{os.getpid()}")
    try:
        engine = detect_engine(engine_pref)
        repo_name = sanitize_repo_name(repo_url)
        container_name = f"healt-sandbox-{repo_name}-{os.getpid()}"
        print_siem_banner(engine, repo_url, target_dest)
        print(f"{_color('[INF]', '36')} stage  : 1/3 static signature scan")
        temp_extract_dir.mkdir(parents=True, exist_ok=True)
        extracted_repo_dir = temp_extract_dir / repo_name
        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--config",
                    "core.hooksPath=/dev/null",
                    repo_url,
                    str(extracted_repo_dir),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as exc:
            print(f"{_color('[ERR]', '1;31')} clone failed: {repo_url}")
            return exc.returncode

        structured_findings = scan_workspace_structured(extracted_repo_dir) if extracted_repo_dir.exists() else []
        rate_info = calculate_security_rate(structured_findings)
        print_siem_scan_report(structured_findings, rate_info)
        try:
            record_scan_history(repo_url, rate_info, structured_findings)
        except OSError:
            pass

        revshell_hits = [f for f in structured_findings if f.get("rule_id") == "EXEC-REVSHELL-001"]
        if revshell_hits:
            print(
                f"{_color('[BLK]', '1;97;41')} EXEC-REVSHELL-001 ({len(revshell_hits)} hit) -> auto-close"
            )
            return 3

        if not rate_info["allowed"] and not force:
            print(
                f"{_color('[BLK]', '1;31')} rate={rate_info['score']}% -> blocked (use --force to override)"
            )
            return 2

        print(f"{_color('[INF]', '36')} stage  : 2/3 sandbox container")
        if engine is None:
            print(f"{_color('[WRN]', '33')} podman/docker not found; running static scan only")
        else:
            target_sandbox_tag = (
                DEFAULT_SANDBOX_IMAGE
                if image == "python:3.12-slim"
                else f"healt-sandbox-{re.sub(r'[^A-Za-z0-9._-]', '_', image)}:latest"
            )
            runtime_image = ensure_sandbox_image(engine, image, target_sandbox_tag)
            setup_script_parts = [
                "set -e",
                "mkdir -p /tmp/sandbox && cd /tmp/sandbox",
                f"git clone --depth 1 --config core.hooksPath=/dev/null '{repo_url}' '{repo_name}'",
                f"cd '{repo_name}'",
            ]
            if install_cmd.strip():
                setup_script_parts.append(install_cmd.strip())
            setup_cmd = build_hardened_base_cmd(
                engine=engine,
                image=runtime_image,
                container_name=container_name,
                memory=memory,
                cpus=cpus,
                pids_limit=pids_limit,
                interactive=False,
            ) + ["sh", "-lc", " && ".join(setup_script_parts)]
            try:
                run_cmd(setup_cmd, check=True)
            except subprocess.CalledProcessError as exc:
                print(f"{_color('[ERR]', '1;31')} sandbox setup exit {exc.returncode}")
                return exc.returncode

            if test_cmd.strip():
                test_container_name = f"{container_name}-test"
                t_cmd = build_hardened_base_cmd(
                    engine=engine,
                    image=runtime_image,
                    container_name=test_container_name,
                    memory=memory,
                    cpus=cpus,
                    pids_limit=pids_limit,
                    network_mode="none",
                    interactive=False,
                ) + ["sh", "-lc", f"cd /tmp/sandbox/'{repo_name}' && {test_cmd.strip()}"]
                try:
                    run_cmd(t_cmd, check=True)
                except subprocess.CalledProcessError as exc:
                    print(f"{_color('[WRN]', '33')} smoke test exit {exc.returncode}")

            if shell:
                shell_container_name = f"{container_name}-shell"
                s_cmd = build_hardened_base_cmd(
                    engine=engine,
                    image=runtime_image,
                    container_name=shell_container_name,
                    memory=memory,
                    cpus=cpus,
                    pids_limit=pids_limit,
                    network_mode="none",
                    interactive=True,
                ) + [
                    "sh",
                    "-lc",
                    f"cd /tmp/sandbox/'{repo_name}' && "
                    f"(command -v bash >/dev/null 2>&1 && exec bash || exec sh)",
                ]
                subprocess.run(s_cmd, check=False)

        print(f"{_color('[INF]', '36')} stage  : 3/3 host placement")
        warn_tag = "[FORCE] " if not rate_info["allowed"] and force else ""
        try:
            answer = (
                input(f"{_color('[INF]', '36')} {warn_tag}copy '{repo_name}' -> '{target_dest}'? [y/N]: ")
                .strip()
                .lower()
            )
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        if answer in {"y", "yes"} and extracted_repo_dir.exists():
            try:
                final_path = promote_to_host(extracted_repo_dir, target_dest, repo_name, force=force)
                print(f"{_color('[INF]', '1;32')} saved : {final_path}")
            except Exception as exc:
                print(f"{_color('[ERR]', '1;31')} {exc}")
                return 1
        else:
            print(f"{_color('[INF]', '33')} skipped host placement")
        return 0
    except KeyboardInterrupt:
        print(f"\n{_color('[WRN]', '33')} interrupted")
        return 130
    finally:
        if temp_extract_dir.exists():
            shutil.rmtree(temp_extract_dir, ignore_errors=True)
