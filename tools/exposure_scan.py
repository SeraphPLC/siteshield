#!/usr/bin/env python3
"""Redacting SiteShield source/Git-history exposure scanner.

The scanner reports detector names, paths, line numbers, and historical object
IDs only. It never prints or stores matched secret values.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

SCHEMA_VERSION = "siteshield-exposure-scan-v1"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024

_PROVIDER_PATTERNS = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b")),
    ("GITHUB_FINE_GRAINED_TOKEN", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,255}\b")),
    ("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("STRIPE_LIVE_SECRET", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
    ("OPENAI_STYLE_KEY", re.compile(r"\bsk-(?:proj-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{32,})\b")),
)

_GENERIC_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b
    (?:
        api[_-]?key |
        access[_-]?token |
        refresh[_-]?token |
        auth[_-]?token |
        bearer[_-]?token |
        client[_-]?secret |
        secret |
        password |
        passwd |
        credential |
        private[_-]?key
    )
    \b
    \s*[:=]\s*
    ["']?
    (?P<value>[A-Za-z0-9_+/.=@:-]{16,})
    """
)

_BEARER_LITERAL = re.compile(
    r"""(?ix)
    \b(?:authorization|auth)\b\s*[:=]\s*["']?
    bearer\s+(?P<value>[A-Za-z0-9._~+/=-]{16,})
    """
)

_PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "redacted",
    "dummy",
    "fake",
    "sample",
    "test",
    "testing",
    "changeme",
    "replace_me",
    "replace-me",
    "your_",
    "your-",
    "runtime",
    "supplied",
    "not-a-secret",
    "not_a_secret",
    "xxxx",
)


@dataclass(frozen=True)
class Finding:
    detector: str
    path: str
    line: int
    object_id: Optional[str] = None


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    counts = {ch: value.count(ch) for ch in set(value)}
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _looks_placeholder(value: str) -> bool:
    stripped = value.strip().strip('"\'')
    lowered = stripped.lower()
    if not stripped:
        return True
    if stripped.startswith(("$", "${", "<")):
        return True
    if "..." in stripped:
        return True
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    if len(set(stripped)) <= 3:
        return True
    return False


def _credible_generic(value: str) -> bool:
    if len(value) < 20 or _looks_placeholder(value):
        return False
    categories = sum(
        bool(pattern.search(value))
        for pattern in (
            re.compile(r"[a-z]"),
            re.compile(r"[A-Z]"),
            re.compile(r"[0-9]"),
            re.compile(r"[^A-Za-z0-9]"),
        )
    )
    return categories >= 2 and _entropy(value) >= 3.3


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def scan_bytes(data: bytes, path: str, object_id: Optional[str] = None) -> list[Finding]:
    """Scan one blob without returning matched values."""
    if _is_binary(data):
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        for detector, pattern in _PROVIDER_PATTERNS:
            if pattern.search(line):
                key = (detector, line_number)
                if key not in seen:
                    findings.append(Finding(detector, path, line_number, object_id))
                    seen.add(key)

        for detector, pattern in (
            ("GENERIC_SECRET_ASSIGNMENT", _GENERIC_ASSIGNMENT),
            ("BEARER_LITERAL", _BEARER_LITERAL),
        ):
            for match in pattern.finditer(line):
                value = match.group("value")
                if _credible_generic(value):
                    key = (detector, line_number)
                    if key not in seen:
                        findings.append(Finding(detector, path, line_number, object_id))
                        seen.add(key)
                    break

    return findings


def _git(root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        message = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {message}")
    return proc.stdout


def _tracked_paths(root: Path) -> list[str]:
    raw = _git(root, "ls-files", "-z")
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in raw.split(b"\0")
        if item
    ]


def _history_blob_index(root: Path) -> list[tuple[str, str, int]]:
    raw = _git(root, "rev-list", "--objects", "--all")
    first_path_by_object: dict[str, str] = {}
    for line in raw.decode("utf-8", errors="replace").splitlines():
        object_id, sep, path = line.partition(" ")
        if sep and path:
            first_path_by_object.setdefault(object_id, path)

    if not first_path_by_object:
        return []

    object_ids = list(first_path_by_object)
    batch_input = ("\n".join(object_ids) + "\n").encode("ascii")
    checked = _git(
        root,
        "cat-file",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        input_bytes=batch_input,
    )
    blobs: list[tuple[str, str, int]] = []
    for line in checked.decode("utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        object_id, object_type, size_text = parts
        if object_type != "blob":
            continue
        try:
            size = int(size_text)
        except ValueError:
            continue
        path = first_path_by_object.get(object_id)
        if path:
            blobs.append((object_id, path, size))
    return blobs


def _batch_blob_contents(
    root: Path, blobs: Iterable[tuple[str, str, int]]
) -> Iterator[tuple[str, str, int, bytes]]:
    proc = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    try:
        for object_id, path, expected_size in blobs:
            proc.stdin.write((object_id + "\n").encode("ascii"))
            proc.stdin.flush()
            header = proc.stdout.readline().decode("utf-8", errors="replace").strip()
            parts = header.split()
            if len(parts) != 3 or parts[1] != "blob":
                raise RuntimeError(f"unexpected git cat-file header for {object_id}")
            size = int(parts[2])
            data = proc.stdout.read(size)
            terminator = proc.stdout.read(1)
            if terminator != b"\n" or len(data) != size or size != expected_size:
                raise RuntimeError(f"incomplete git blob read for {object_id}")
            yield object_id, path, size, data
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        returncode = proc.wait(timeout=10)
        stderr = b""
        if proc.stderr is not None:
            stderr = proc.stderr.read()
            proc.stderr.close()
        if proc.stdout is not None:
            proc.stdout.close()
        if returncode != 0:
            raise RuntimeError(
                "git cat-file --batch failed: "
                + stderr.decode("utf-8", errors="replace").strip()
            )


def scan_repository(
    root: Path,
    *,
    history: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict:
    root = root.resolve()
    findings: list[Finding] = []
    scanned = 0
    skipped_binary = 0
    skipped_large = 0

    if history:
        indexed = _history_blob_index(root)
        eligible: list[tuple[str, str, int]] = []
        for object_id, path, size in indexed:
            if size > max_bytes:
                skipped_large += 1
                continue
            eligible.append((object_id, path, size))

        for object_id, path, _size, data in _batch_blob_contents(root, eligible):
            if _is_binary(data):
                skipped_binary += 1
                continue
            scanned += 1
            findings.extend(scan_bytes(data, path, object_id))
        scope = "all-reachable-git-history"
    else:
        for path in _tracked_paths(root):
            full_path = root / path
            try:
                size = full_path.stat().st_size
            except FileNotFoundError:
                continue
            if size > max_bytes:
                skipped_large += 1
                continue
            data = full_path.read_bytes()
            if _is_binary(data):
                skipped_binary += 1
                continue
            scanned += 1
            findings.extend(scan_bytes(data, path))
        scope = "tracked-current-tree"

    findings = sorted(
        set(findings),
        key=lambda item: (item.path, item.line, item.detector, item.object_id or ""),
    )
    status = "FINDINGS" if findings else "PASS"
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": scope,
        "status": status,
        "findings_count": len(findings),
        "scanned_text_blobs": scanned,
        "skipped_binary_blobs": skipped_binary,
        "skipped_large_blobs": skipped_large,
        "max_blob_bytes": max_bytes,
        "findings": [asdict(item) for item in findings],
        "report_contains_matched_values": False,
    }


def _write_report(report: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Redacting SiteShield exposure scanner for tracked source or reachable Git history."
    )
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--json-out")
    args = parser.parse_args(argv)

    try:
        report = scan_repository(
            Path(args.repo_root),
            history=args.history,
            max_bytes=args.max_bytes,
        )
    except Exception as exc:
        print(f"SERAPH_EXPOSURE_SCAN_ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3

    if args.json_out:
        _write_report(report, Path(args.json_out))

    print(
        "SERAPH_EXPOSURE_SCAN "
        f"scope={report['scope']} status={report['status']} "
        f"findings={report['findings_count']} "
        f"scanned={report['scanned_text_blobs']} "
        f"skipped_binary={report['skipped_binary_blobs']} "
        f"skipped_large={report['skipped_large_blobs']}"
    )
    return 2 if report["findings_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
