"""Bound native tool execution. This is a resource guard, not a sandbox."""

from __future__ import annotations

import os
import selectors
import shutil
import signal
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
TOOLS = {
    "file": ["--version"],
    "readelf": ["--version"],
    "openssl": ["version"],
    "exiftool": ["-ver"],
    "curl": ["--version"],
}


@dataclass
class CommandResult:
    argv: list[str]
    status: str
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    output_truncated: bool = False
    stdout_bytes: bytes = field(default=b"", repr=False)

    def to_dict(self) -> dict:
        return {key: value for key, value in asdict(self).items() if key != "stdout_bytes"}


class Runner:
    def __init__(self, timeout: float = 10, max_output: int = 65536):
        if timeout <= 0 or max_output < 1:
            raise ValueError("Runner limits must be positive")
        self.timeout = timeout
        self.max_output = max_output
        self.versions: dict[str, str] = {}

    @staticmethod
    def locate(tool: str) -> str | None:
        # Never search the challenge directory or inherit a modified PATH.
        return shutil.which(tool, path=SYSTEM_PATH)

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def run(self, argv: list[str], cwd: Path) -> CommandResult:
        start = time.monotonic()
        argv = [str(arg) for arg in argv]
        result = CommandResult(argv=argv, status="failed")
        executable = self.locate(argv[0])
        if executable is None:
            result.status = "unavailable"
            result.stderr = f"Required tool is not installed: {argv[0]}"
            return result
        env = {"PATH": SYSTEM_PATH, "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
               "HOME": str(cwd), "TMPDIR": str(cwd), "OPENSSL_CONF": "/dev/null"}
        try:
            proc = subprocess.Popen(
                [executable, *argv[1:]], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, start_new_session=True, close_fds=True,
            )
        except OSError as exc:
            result.stderr = f"{type(exc).__name__}: {exc}"
            return result
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        total = 0
        try:
            with selectors.DefaultSelector() as selector:
                for name in buffers:
                    stream = getattr(proc, name)
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    remaining = self.timeout - (time.monotonic() - start)
                    if remaining <= 0:
                        result.status = "timeout"
                        self._kill_group(proc)
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        room = self.max_output - total
                        buffers[key.data].extend(chunk[:room])
                        total += min(len(chunk), room)
                        if len(chunk) > room:
                            result.output_truncated = True
                            result.status = "partial"
                            self._kill_group(proc)
                            break
                    if result.output_truncated:
                        break
                if result.status not in {"timeout", "partial"}:
                    try:
                        proc.wait(timeout=max(0.001, self.timeout - (time.monotonic() - start)))
                        result.status = "complete" if proc.returncode == 0 else "failed"
                    except subprocess.TimeoutExpired:
                        result.status = "timeout"
        finally:
            # Also clean up descendants that inherited pipe handles or outlived the parent.
            self._kill_group(proc)
            proc.wait()
            proc.stdout.close()
            proc.stderr.close()
        result.returncode = proc.returncode
        result.duration_ms = round((time.monotonic() - start) * 1000)
        result.stdout_bytes = bytes(buffers["stdout"])
        result.stdout = result.stdout_bytes.decode("utf-8", "replace")
        result.stderr = bytes(buffers["stderr"]).decode("utf-8", "replace")
        return result

    def version(self, tool: str, cwd: Path) -> str:
        if tool not in self.versions:
            probe = self.run([tool, *TOOLS[tool]], cwd)
            lines = (probe.stdout or probe.stderr).splitlines()
            self.versions[tool] = lines[0][:240] if lines else probe.status
        return self.versions[tool]
