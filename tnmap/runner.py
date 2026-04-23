"""Async nmap subprocess runner that streams stdout line-by-line."""
from __future__ import annotations

import asyncio
import os
import shlex
import shutil
from collections.abc import AsyncIterator
from pathlib import Path


def find_nmap() -> str | None:
    """Locate the nmap executable, preferring PATH then common Windows install dirs."""
    exe = shutil.which("nmap")
    if exe:
        return exe
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/homebrew/bin/nmap",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None


def build_argv(template: str, target: str) -> list[str]:
    """Resolve {target} placeholder and split into argv.

    Uses shlex with posix=False on Windows-style templates friendly.
    """
    resolved = template.replace("{target}", target).strip()
    posix = os.name != "nt"
    argv = shlex.split(resolved, posix=posix)
    if argv and argv[0].lower().endswith("nmap"):
        argv = argv[1:]
    nmap = find_nmap()
    if not nmap:
        raise FileNotFoundError("nmap executable not found on PATH")
    return [nmap, *argv]


async def stream_nmap(template: str, target: str) -> AsyncIterator[str]:
    """Yield lines of nmap stdout+stderr as they arrive."""
    argv = build_argv(template, target)
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    assert proc.stdout is not None
    while True:
        raw = await proc.stdout.readline()
        if not raw:
            break
        yield raw.decode("utf-8", errors="replace").rstrip("\r\n")
    rc = await proc.wait()
    yield f"\n[exit {rc}]"
