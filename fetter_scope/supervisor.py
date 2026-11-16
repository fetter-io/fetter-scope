"""Launch, read, restart and stop fetter; its control channel; following a stream file.

`Supervisor` runs one long-lived `fetter ... monitor-diff ... --control stdin json` child (see
SPEC: Contract with fetter). Every stdout event, and fetter-scope's own entries (`events.own`:
launch, exits, stderr lines, commands sent, protocol errors), go to one `sink` in order.

- Unexpected exits restart fetter with exponential backoff; `max_failures` exits in a row with no
  `scan` event between them stop the restarts (status "failed").
- `stop()` writes `stop`, waits for fetter to finish its scan and exit, then terminates it.
  An exit with 0 or 3 after `stop` is clean: fetter 5.0.0 exits with 3 when its last report was
  an alert.
- `request("scan" | "report")` keeps at most one request outstanding; the next `request` scan
  acknowledges it (for `report`, the report that follows it, or failing that the next event or a
  grace period, since with `--report change` no report is written when nothing changed).

`follow` reads a stream file (or the `events/` directory) and then follows what is appended:
attach mode, which has no control channel.
"""
import asyncio
import os
import signal
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from fetter_scope.events import Parsed, own, parse_line, summary, duration_seconds
from fetter_scope.store import Store

if TYPE_CHECKING:
    from fetter_scope.scheduler import Mailer

LINE_LIMIT = 64 * 1024 * 1024        # one report can be large; asyncio's default is 64 KiB
CLEAN_STOP_CODES = (0, 3)
UNKNOWN_COMMAND = "Unknown control command"

Sink = Callable[[Parsed], None]


@dataclass(frozen=True)
class Timing:
    backoff_initial: float = 5
    backoff_max: float = 600
    max_failures: int = 3
    stop_timeout: float = 30           # for fetter to finish a scan after `stop`
    kill_timeout: float = 5            # after terminate, before kill
    request_timeout: float = 600       # for the `request` scan acknowledging a command
    report_grace: float = 120          # after a `report` request's scan, for its report


@dataclass
class _Pending:
    command: str
    future: asyncio.Future
    phase: str = "scan"                # "scan": awaiting the request scan; "report": its report
    scan: dict | None = None
    timer: asyncio.TimerHandle | None = None


class Supervisor:
    def __init__(self, cmd: list[str], sink: Sink, store: Store | None = None,
                 timing: Timing = Timing()):
        self.cmd = list(cmd)
        self.sink = sink
        self.store = store
        self.timing = timing
        self.status = "idle"           # starting, running, restarting, stopping, stopped, failed
        self.proc: asyncio.subprocess.Process | None = None
        self.pending: _Pending | None = None
        self.failures = 0              # exits since the last scan event
        self.backoff = timing.backoff_initial
        self.stopping = False
        self._terminated = False
        self._stop_event = asyncio.Event()

    # main loop ----------------------------------------------------------------

    async def run(self) -> None:
        """Run fetter until `stop()`, or until restarts stop after repeated failures."""
        while not self.stopping:
            self.status = "starting"
            code, message = await self._run_once()
            if self.stopping:
                self._emit("fetter-exit", code=code, expected=True,
                           **({"terminated": True} if self._terminated else {}))
                break
            self.failures += 1
            extra = {"message": message} if message else {}
            if self.failures >= self.timing.max_failures:
                self._emit("fetter-exit", code=code, expected=False, **extra)
                self._emit("supervisor-error", message=(
                    f"fetter exited {self.failures} times in a row without completing a scan; "
                    "not restarting"))
                self.status = "failed"
                return
            self._emit("fetter-exit", code=code, expected=False, restart_in=self.backoff, **extra)
            self.status = "restarting"
            try:
                await asyncio.wait_for(self._stop_event.wait(), self.backoff)
            except TimeoutError:
                pass
            self.backoff = min(self.backoff * 2, self.timing.backoff_max)
        self.status = "stopped"

    async def _run_once(self) -> tuple[int | None, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *self.cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, limit=LINE_LIMIT,
                # Its own session: a terminal's Ctrl-C reaches fetter-scope, which stops fetter.
                start_new_session=os.name == "posix")
        except OSError as e:
            return None, f"cannot launch {self.cmd[0]}: {e.strerror or e}"
        self.proc = proc
        if self.store is not None:
            self.store.update_state(fetter={"pid": proc.pid, "binary": self.cmd[0],
                                            "started": time.time()})
        self._emit("launch", pid=proc.pid, command=self.cmd)
        if self.stopping:              # stop() arrived while launching
            self.status = "stopping"
            stopper = asyncio.create_task(self._stop_proc(proc))
        else:
            self.status, stopper = "running", None
        await asyncio.gather(self._read_stdout(proc), self._read_stderr(proc))
        code = await proc.wait()
        if stopper is not None:
            await stopper
        self.proc = None
        self._resolve(None)
        if self.store is not None:
            self.store.update_state(fetter=None)
        return code, ""

    async def _read_stdout(self, proc: asyncio.subprocess.Process) -> None:
        while True:
            try:
                line = await proc.stdout.readline()
            except ValueError:
                self._emit("stdout", line="", problem=f"a line over {LINE_LIMIT} bytes was dropped")
                continue
            if not line:
                return
            p = parse_line(line)
            if p.event is None:
                if p.line.strip():
                    self._emit("stdout", line=p.line, problem=p.problem)
                continue
            self.sink(p)
            self._on_event(p)

    async def _read_stderr(self, proc: asyncio.subprocess.Process) -> None:
        while True:
            try:
                line = await proc.stderr.readline()
            except ValueError:
                continue
            if not line:
                return
            text = line.decode("utf-8", errors="replace").rstrip("\r\n")
            if text:
                self._emit("stderr", line=text)

    # events and the control channel -------------------------------------------

    def _emit(self, kind: str, **fields) -> None:
        self.sink(own(kind, **fields))

    def _on_event(self, p: Parsed) -> None:
        e, pending = p.event, self.pending
        if p.kind == "scan":
            self.failures = 0
            self.backoff = self.timing.backoff_initial
            if pending is None:
                return
            if pending.phase == "report":
                # another scan, so no report followed the request scan (nothing changed)
                self._resolve(pending.scan)
            elif e.get("trigger") == "request":
                if pending.command == "scan":
                    self._resolve(e)
                else:
                    pending.phase, pending.scan = "report", e
                    self._arm(pending, self.timing.report_grace)
        elif p.kind == "report":
            if pending is not None and pending.phase == "report":
                self._resolve(e)
        elif p.kind == "error":
            message = str(e.get("message", ""))
            if message.startswith(UNKNOWN_COMMAND):
                self._emit("protocol-error", message=message)
                self._resolve(None)

    def _arm(self, pending: _Pending, seconds: float) -> None:
        if pending.timer is not None:
            pending.timer.cancel()
        pending.timer = asyncio.get_running_loop().call_later(seconds, self._expire, pending)

    def _expire(self, pending: _Pending) -> None:
        if self.pending is not pending:
            return
        if pending.phase == "report":
            self._resolve(pending.scan)
        else:
            self._emit("protocol-error", message=(
                f"no response to {pending.command!r} within {self.timing.request_timeout:g}s"))
            self._resolve(None)

    def _resolve(self, value: dict | None) -> None:
        pending, self.pending = self.pending, None
        if pending is None:
            return
        if pending.timer is not None:
            pending.timer.cancel()
        if not pending.future.done():
            pending.future.set_result(value)

    async def _write(self, proc: asyncio.subprocess.Process, command: str) -> bool:
        """Write one command; on a broken pipe, terminate fetter so the exit handling applies."""
        try:
            if proc.stdin is None or proc.stdin.is_closing():
                raise BrokenPipeError("stdin is closed")
            proc.stdin.write(command.encode() + b"\n")
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError) as e:
            self._emit("protocol-error", message=f"cannot write {command!r} to fetter: {e}")
            if proc.returncode is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
            return False
        self._emit("control", command=command)
        return True

    @property
    def can_request(self) -> bool:
        return (self.pending is None and not self.stopping and self.proc is not None
                and self.proc.returncode is None)

    async def request(self, command: str) -> asyncio.Future | None:
        """Write `scan` or `report`. Returns a future of the acknowledging event (None if the
        request failed or timed out), or None if not sent: one is outstanding, or fetter is not
        running."""
        if command not in ("scan", "report"):
            raise ValueError(f"not a request command: {command!r}")
        if not self.can_request:
            return None
        proc = self.proc
        future = asyncio.get_running_loop().create_future()
        pending = self.pending = _Pending(command, future)
        self._arm(pending, self.timing.request_timeout)
        if not await self._write(proc, command):
            self._resolve(None)
            return None
        return future

    async def stop(self) -> None:
        """Write `stop`, wait for fetter to exit, then terminate it. A second call while
        stopping terminates at once."""
        proc = self.proc
        if self.stopping:
            if proc is not None and proc.returncode is None:
                self._terminated = True
                proc.terminate()
            return
        self.stopping = True
        self.status = "stopping"
        self._stop_event.set()
        if proc is None or proc.returncode is not None:
            return                     # not running; run() will not (re)launch, or stops it
        await self._stop_proc(proc)

    async def _stop_proc(self, proc: asyncio.subprocess.Process) -> None:
        await self._write(proc, "stop")
        try:
            await asyncio.wait_for(proc.wait(), self.timing.stop_timeout)
            return
        except TimeoutError:
            pass
        self._terminated = True
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), self.timing.kill_timeout)
        except ProcessLookupError:
            pass
        except TimeoutError:
            proc.kill()
            await proc.wait()


#-------------------------------------------------------------------------------
# a fetter left running by an earlier fetter-scope

def _command_line(pid: int) -> str | None:
    """The process's command line, or None if it is not running (POSIX)."""
    proc_file = Path(f"/proc/{pid}/cmdline")
    if proc_file.exists():
        try:
            return proc_file.read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            return None
    try:
        out = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # a zombie (exited, not reaped) counts as gone
    stat = Path(f"/proc/{pid}/stat")
    try:
        return stat.read_text().split(")")[-1].split()[0] != "Z"
    except (OSError, IndexError):
        return True


def stop_stale(store: Store, sink: Sink | None = None, timeout: float = 5) -> int | None:
    """Stop the fetter recorded in state.json if it is still running (fetter-scope exited
    without stopping it, so its stdin is gone and `stop` cannot be sent). Returns its pid."""
    rec = store.read_state().get("fetter")
    if not isinstance(rec, dict):
        return None
    store.update_state(fetter=None)
    pid, binary = rec.get("pid"), rec.get("binary")
    if os.name != "posix" or not isinstance(pid, int) or not isinstance(binary, str):
        return None
    cmdline = _command_line(pid)
    if not cmdline or binary not in cmdline or "monitor-diff" not in cmdline:
        return None                    # gone, or the pid now belongs to something else
    try:
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + timeout
        while _alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if _alive(pid):
            os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if sink is not None:
        sink(own("stale-stop", pid=pid))
    return pid


#-------------------------------------------------------------------------------
# attach: follow a file fetter (or fetter-scope) writes

class _Tail:
    """Complete lines appended to a file since the last read; reopens if it is replaced or
    truncated."""

    def __init__(self, path: Path):
        self.path = path
        self.fh = None
        self.ino = None
        self.buf = b""

    def _open(self) -> bool:
        try:
            self.fh = open(self.path, "rb")
        except FileNotFoundError:
            return False
        self.ino = os.fstat(self.fh.fileno()).st_ino
        self.buf = b""
        return True

    def read(self) -> list[bytes]:
        if self.fh is None and not self._open():
            return []
        lines = self._drain()
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return lines
        if st.st_ino != self.ino:          # replaced: finish the old file, then the new one
            self.close()
            if self._open():
                lines += self._drain()
        elif st.st_size < self.fh.tell():  # truncated
            self.fh.seek(0)
            self.buf = b""
            lines += self._drain()
        return lines

    def _drain(self) -> list[bytes]:
        data = self.fh.read()
        if not data:
            return []
        parts = (self.buf + data).split(b"\n")
        self.buf = parts.pop()
        return [p for p in parts if p.strip()]

    def close(self) -> None:
        if self.fh is not None:
            self.fh.close()
            self.fh = None


def _latest(directory: Path) -> Path | None:
    files = sorted(directory.glob("*.jsonl"))
    return files[-1] if files else None


async def follow(path: Path, sink: Sink, *, poll: float = 0.5,
                 stop: asyncio.Event | None = None) -> None:
    """Read `path` from its start, then follow appended lines until `stop` is set.

    `path` is a stream file (`monitor-diff json -o FILE`), or a directory of daily `.jsonl`
    files (fetter-scope's `events/`): all are read in order, then the newest is followed,
    moving to a newer one when it appears.
    """
    stop = stop or asyncio.Event()
    directory = path if path.is_dir() else None
    if directory is not None:
        current = _latest(directory)
        for f in sorted(directory.glob("*.jsonl")):
            if current is not None and f < current:
                with open(f, "rb") as fh:
                    for line in fh:
                        if line.strip():
                            sink(parse_line(line))
    else:
        current = path
    tail = _Tail(current) if current is not None else None
    try:
        while True:
            if tail is not None:
                for line in tail.read():
                    sink(parse_line(line))
            if directory is not None:
                newest = _latest(directory)
                if newest is not None and (current is None or newest > current):
                    if tail is not None:
                        for line in tail.read():
                            sink(parse_line(line))
                        tail.close()
                    current, tail = newest, _Tail(newest)
                    continue
            try:
                await asyncio.wait_for(stop.wait(), poll)
                return
            except TimeoutError:
                pass
    finally:
        if tail is not None:
            tail.close()


#-------------------------------------------------------------------------------
# headless

def stamp(p: Parsed) -> str:
    t = duration_seconds(p.event.get("time")) if p.event else None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() if t is None else t))


def log_line(p: Parsed) -> str:
    return f"{stamp(p)}  {summary(p)}"


@dataclass
class Headless:
    """`run --headless`: the supervisor, the event log and mail, printing one line per entry."""
    cmd: list[str]
    store: Store
    out: Callable[[str], None] = print
    retention_days: int = 90
    timing: Timing = field(default_factory=Timing)
    prune_every: float = 3600
    mailer: "Mailer | None" = None
    mail_every: float = 30

    def __post_init__(self):
        self._tasks: set[asyncio.Task] = set()

    def sink(self, p: Parsed) -> None:
        self.store.append(p)
        self.out(log_line(p))
        if self.mailer is not None and self.mailer.on_entry(p):
            task = asyncio.get_running_loop().create_task(self._mail_tick())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _mail_tick(self) -> None:
        try:
            await self.mailer.tick()
        except Exception as e:               # mail must never stop monitoring
            self.sink(own("supervisor-error", message=f"mail: {type(e).__name__}: {e}"))

    async def run(self) -> int:
        stop_stale(self.store, self.sink)
        self.store.prune(self.retention_days)
        if self.mailer is not None:
            self.mailer.emit = self.sink
            self.mailer.start()
            self.out(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {self.mailer.status()}")
        sup = self.supervisor = Supervisor(self.cmd, self.sink, self.store, self.timing)
        loop = asyncio.get_running_loop()
        signals = []
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.ensure_future(sup.stop()))
                signals.append(sig)
            except (NotImplementedError, RuntimeError):
                pass

        async def prune():
            while True:
                await asyncio.sleep(self.prune_every)
                self.store.prune(self.retention_days)

        async def mail():
            while True:                      # the first tick sends a digest missed while down
                await self._mail_tick()
                await asyncio.sleep(self.mail_every)

        background = [asyncio.create_task(prune())]
        if self.mailer is not None:
            background.append(asyncio.create_task(mail()))
        try:
            await sup.run()
        finally:
            for task in background + list(self._tasks):
                task.cancel()
            await asyncio.gather(*background, *self._tasks, return_exceptions=True)
            for sig in signals:
                loop.remove_signal_handler(sig)
            self.store.close()
        return 0 if sup.status == "stopped" else 1


def print_followed(out: Callable[[str], None] = print) -> Sink:
    return lambda p: out(log_line(p))

