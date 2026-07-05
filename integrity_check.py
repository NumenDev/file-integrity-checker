#!/usr/bin/env python3
"""
integrity-check -- Log file integrity checker.

Computes SHA-256 hashes of log files and stores them in a baseline
database. The database is signed with HMAC-SHA256 (key generated on
first use), so tampering with the database itself is also detected.

Usage:
    integrity-check init   <file-or-dir> [--pattern GLOB]
    integrity-check check  <file-or-dir> [--pattern GLOB]
    integrity-check update <file-or-dir> [--pattern GLOB]

Exit codes:
    0  all files unmodified
    1  discrepancies found (modified / new / missing files)
    2  error (no database, database tampered with, bad arguments, ...)

The baseline lives in ~/.integrity-check/ by default; override with the
INTEGRITY_CHECK_HOME environment variable.
"""

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

DB_HOME = Path(os.environ.get("INTEGRITY_CHECK_HOME", "") or (Path.home() / ".integrity-check"))
DB_FILE = DB_HOME / "hashes.json"
KEY_FILE = DB_HOME / "secret.key"
CHUNK_SIZE = 1024 * 1024


# ---------------------------------------------------------------- hashing

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


# ------------------------------------------------------- secure baseline

def _restrict_permissions(path: Path) -> None:
    """Best effort: make the baseline readable only by the current user."""
    try:
        if os.name == "nt":
            user = os.environ.get("USERNAME") or os.getlogin()
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                capture_output=True,
            )
        else:
            path.chmod(0o700 if path.is_dir() else 0o600)
    except OSError:
        pass


def _load_key() -> bytes:
    if KEY_FILE.exists():
        return bytes.fromhex(KEY_FILE.read_text().strip())
    DB_HOME.mkdir(parents=True, exist_ok=True)
    _restrict_permissions(DB_HOME)
    key = secrets.token_bytes(32)
    KEY_FILE.write_text(key.hex())
    _restrict_permissions(KEY_FILE)
    return key


def _sign(key: bytes, entries: dict) -> str:
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()


def load_db(for_init: bool = False) -> dict:
    """Return {normalized_path: {"sha256": ..., "size": ..., "mtime": ...}}."""
    if not DB_FILE.exists():
        if not for_init:
            fail(f"No hash database found at {DB_FILE}. Run 'init' first.")
        return {}
    try:
        raw = json.loads(DB_FILE.read_text(encoding="utf-8-sig"))
        entries = raw.get("files", {})
        authentic = isinstance(entries, dict) and hmac.compare_digest(
            _sign(_load_key(), entries), str(raw.get("hmac", ""))
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, AttributeError):
        entries, authentic = {}, False
    if not authentic:
        warning = (
            "SECURITY WARNING: the hash database failed its own integrity check\n"
            f"(HMAC mismatch or corruption on {DB_FILE}). The database may have\n"
            "been tampered with and cannot be trusted."
        )
        if not for_init:
            fail(warning + " Re-run 'init' to rebuild it.")
        print(f"{warning}\nDiscarding it and rebuilding from scratch.", file=sys.stderr)
        return {}
    return entries


def save_db(entries: dict) -> None:
    DB_HOME.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "files": entries, "hmac": _sign(_load_key(), entries)}
    tmp = DB_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(DB_FILE)
    _restrict_permissions(DB_FILE)


# ------------------------------------------------------------- helpers

def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


def normalize(path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def collect_files(target: Path, pattern: str | None) -> list[Path]:
    """All regular files under target (or target itself), excluding the baseline."""
    internal = {normalize(DB_FILE), normalize(KEY_FILE)}
    if target.is_file():
        files = [target]
    else:
        files = sorted(p for p in target.rglob("*") if p.is_file())
    if pattern:
        files = [p for p in files if fnmatch.fnmatch(p.name, pattern)]
    return [p for p in files if normalize(p) not in internal]


def baseline_paths_under(entries: dict, target: Path) -> list[str]:
    norm = normalize(target)
    prefix = norm.rstrip(os.sep) + os.sep
    return [k for k in entries if k == norm or k.startswith(prefix)]


def make_entry(path: Path) -> dict:
    stat = path.stat()
    return {"sha256": sha256_file(path), "size": stat.st_size, "mtime": stat.st_mtime}


# ------------------------------------------------------------- commands

def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        fail(f"path not found: {target}")
    files = collect_files(target, args.pattern)
    if not files:
        fail(f"no files to hash under {target}")

    entries = load_db(for_init=True)
    for stale in baseline_paths_under(entries, target):
        del entries[stale]  # manual re-initialization drops the old baseline
    for path in files:
        entries[normalize(path)] = make_entry(path)
    save_db(entries)
    print(f"Hashes stored successfully. ({len(files)} file(s), database: {DB_FILE})")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        fail(f"path not found: {target}")
    entries = load_db()
    files = collect_files(target, args.pattern)

    results: list[tuple[str, Path]] = []
    for path in files:
        stored = entries.get(normalize(path))
        if stored is None:
            results.append(("NEW", path))
        else:
            try:
                current = sha256_file(path)
            except OSError as exc:
                fail(f"cannot read {path}: {exc}")
            results.append(("OK" if current == stored["sha256"] else "MODIFIED", path))

    missing = [
        k for k in baseline_paths_under(entries, target) if not os.path.exists(k)
    ]

    counts = {"OK": 0, "MODIFIED": 0, "NEW": 0}
    for status, _ in results:
        counts[status] += 1

    if target.is_file() and len(results) == 1:
        # Single-file mode: terse output as in the spec.
        status = results[0][0]
        if status == "OK":
            print("Status: Unmodified")
        elif status == "MODIFIED":
            print("Status: Modified (Hash mismatch)")
        else:
            fail(f"{target} is not in the baseline. Run 'init' or 'update' on it first.")
        return 0 if status == "OK" else 1

    labels = {"OK": "[OK]      ", "MODIFIED": "[MODIFIED]", "NEW": "[NEW]     "}
    for status, path in results:
        note = ""
        if status == "MODIFIED":
            note = "  (hash mismatch)"
        elif status == "NEW":
            note = "  (not in baseline)"
        print(f"{labels[status]} {path}{note}")
    for k in missing:
        print(f"[MISSING]  {k}  (in baseline but not on disk)")

    print(
        f"\nChecked {len(results)} file(s): {counts['OK']} unmodified, "
        f"{counts['MODIFIED']} modified, {counts['NEW']} new, {len(missing)} missing."
    )
    tampered = counts["MODIFIED"] + counts["NEW"] + len(missing)
    print("Status: Modified (Hash mismatch)" if tampered else "Status: Unmodified")
    return 1 if tampered else 0


def cmd_update(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        fail(f"path not found: {target}")
    entries = load_db()
    files = collect_files(target, args.pattern)
    if not files:
        fail(f"no files to hash under {target}")

    for gone in [k for k in baseline_paths_under(entries, target) if not os.path.exists(k)]:
        del entries[gone]
        print(f"Removed from baseline (file no longer exists): {gone}")
    for path in files:
        entries[normalize(path)] = make_entry(path)
    save_db(entries)
    print(f"Hash updated successfully. ({len(files)} file(s))")
    return 0


# ------------------------------------------------------------------ CLI

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="integrity-check",
        description="Verify the integrity of log files using SHA-256 hashes.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name, handler, help_text in (
        ("init", cmd_init, "compute and store baseline hashes (re-running re-initializes)"),
        ("check", cmd_check, "compare current hashes against the stored baseline"),
        ("update", cmd_update, "recompute and store hashes for the given path"),
    ):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("path", help="log file or directory")
        cmd.add_argument(
            "--pattern",
            metavar="GLOB",
            help="only consider files matching this glob (e.g. \"*.log\")",
        )
        cmd.set_defaults(handler=handler)

    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
