import asyncio
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from fetter_scope.store import Store
from fetter_scope.supervisor import Headless, Supervisor, Timing, stop_stale

FAKE = Path(__file__).parent / "fake_fetter.py"
STREAMS = Path(__file__).parent / "fixtures" / "streams"

FAST = Timing(backoff_initial=0.05, backoff_max=0.2, max_failures=3, stop_timeout=3,
              kill_timeout=3, request_timeout=5, report_grace=0.5)
# for a fake fetter that cannot obey `stop` (stdin closed, or every command misread)
DEAF = Timing(**{**FAST.__dict__, "stop_timeout": 0.2})


def cmd(*flags: str) -> list[str]:
    return [sys.executable, "-u", str(FAKE), "monitor-diff", "--control", "stdin", "json", *flags]


class Rec(list):
    """A sink recording entries, with a way to wait for one."""

    def __call__(self, p):
        self.append(p)

    def kinds(self) -> list[str]:
        return [p.kind for p in self]

    def of(self, kind: str) -> list[dict]:
        return [p.event for p in self if p.kind == kind]

    async def wait(self, pred, timeout: float = 10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if pred(self):
                return
            await asyncio.sleep(0.02)
        raise AssertionError(f"timed out; entries: {self.kinds()}")


def count(kind: str, n: int = 1):
    return lambda rec: len(rec.of(kind)) >= n


async def started(*flags, timing=FAST, store=None, scans=1):
    rec = Rec()
    sup = Supervisor(cmd(*flags), rec, store, timing)
    task = asyncio.create_task(sup.run())
    await rec.wait(count("scan", scans))
    return sup, rec, task


async def stopped(sup, task):
    await sup.stop()
    await asyncio.wait_for(task, 10)


# reading and stopping ---------------------------------------------------------

async def test_reads_events_and_stops():
    sup, rec, task = await started()
    assert sup.status == "running"
    await stopped(sup, task)
    assert rec.kinds() == ["launch", "start", "scan", "control", "fetter-exit"]
    assert rec.of("control") == [rec.of("control")[0]] and rec.of("control")[0]["command"] == "stop"
    assert rec.of("fetter-exit")[0]["code"] == 0 and rec.of("fetter-exit")[0]["expected"]
    assert sup.status == "stopped"
    assert all(p.own for p in rec if p.kind in ("launch", "control", "fetter-exit"))


async def test_replays_fixture_stream():
    sup, rec, task = await started("--fake-replay", str(STREAMS / "changes.jsonl"), scans=3)
    await rec.wait(count("error"))
    await stopped(sup, task)
    assert rec.kinds()[1:7] == ["start", "scan", "scan", "scan", "report", "error"]
    # an error event that is fetter's answer to an unknown command is also a protocol error
    assert rec.kinds()[7] == "protocol-error"


async def test_stderr_and_raw_stdout():
    sup, rec, task = await started("--fake-stderr", "warning: x", "--fake-raw", "not json")
    await rec.wait(count("stdout"))
    await stopped(sup, task)
    assert rec.of("stderr")[0]["line"] == "warning: x"
    assert rec.of("stdout")[0]["line"] == "not json"
    assert "not JSON" in rec.of("stdout")[0]["problem"]


async def test_stop_code_3_is_clean():
    sup, rec, task = await started("--fake-stop-code", "3")
    await stopped(sup, task)
    assert rec.of("fetter-exit")[-1] == rec.of("fetter-exit")[-1] | {"code": 3, "expected": True}
    assert sup.status == "stopped"


async def test_stop_terminates_after_timeout():
    t = Timing(**{**FAST.__dict__, "stop_timeout": 0.3})
    sup, rec, task = await started("--fake-ignore-stop", timing=t)
    t0 = time.monotonic()
    await stopped(sup, task)
    assert time.monotonic() - t0 < 3
    exit_ = rec.of("fetter-exit")[-1]
    assert exit_["expected"] and exit_["terminated"] and exit_["code"] != 0


async def test_state_records_pid(home):
    store = Store(home)
    sup, rec, task = await started(store=store)
    state = store.read_state()["fetter"]
    assert state["pid"] == rec.of("launch")[0]["pid"] and state["binary"] == sys.executable
    await stopped(sup, task)
    assert "fetter" not in store.read_state()


# restarts ---------------------------------------------------------------------

async def test_restart_with_backoff(tmp_path):
    runs = tmp_path / "runs"
    sup, rec, task = await started("--fake-runs", str(runs), "--fake-fail-first", "2")
    exits = rec.of("fetter-exit")
    assert [e["restart_in"] for e in exits] == [0.05, 0.1]
    assert all(not e["expected"] and e["code"] == 1 for e in exits)
    assert len(rec.of("launch")) == 3
    assert sup.failures == 0 and sup.backoff == FAST.backoff_initial   # reset by the scan
    await stopped(sup, task)


async def test_three_exits_without_scan_stop_restarts(tmp_path):
    rec = Rec()
    sup = Supervisor(cmd("--fake-fail-first", "99"), rec, None, FAST)
    await asyncio.wait_for(sup.run(), 10)
    assert sup.status == "failed"
    assert len(rec.of("launch")) == 3
    assert [("restart_in" in e) for e in rec.of("fetter-exit")] == [True, True, False]
    assert "3 times in a row" in rec.of("supervisor-error")[0]["message"]


async def test_launch_failure_counts_as_exit(tmp_path):
    rec = Rec()
    sup = Supervisor([str(tmp_path / "nope")], rec, None, FAST)
    await asyncio.wait_for(sup.run(), 10)
    assert sup.status == "failed"
    assert "cannot launch" in rec.of("fetter-exit")[0]["message"]


async def test_stop_during_backoff(tmp_path):
    t = Timing(**{**FAST.__dict__, "backoff_initial": 30})
    rec = Rec()
    sup = Supervisor(cmd("--fake-fail-first", "99"), rec, None, t)
    task = asyncio.create_task(sup.run())
    await rec.wait(count("fetter-exit"))
    await stopped(sup, task)
    assert sup.status == "stopped" and len(rec.of("launch")) == 1


# control channel --------------------------------------------------------------

async def test_scan_request_ack_and_one_outstanding():
    sup, rec, task = await started("--fake-delay", "0.3")
    fut = await sup.request("scan")
    assert fut is not None and not sup.can_request
    assert await sup.request("scan") is None          # ignored while outstanding
    assert await sup.request("report") is None
    ack = await asyncio.wait_for(fut, 5)
    assert ack["event"] == "scan" and ack["trigger"] == "request"
    assert sup.can_request
    assert [e["command"] for e in rec.of("control")] == ["scan"]
    await stopped(sup, task)


async def test_report_request_acked_by_report():
    sup, rec, task = await started()
    ack = await asyncio.wait_for(await sup.request("report"), 5)
    assert ack["event"] == "report"
    await stopped(sup, task)


async def test_report_request_without_report_acked_by_scan_after_grace():
    sup, rec, task = await started("--fake-no-report")
    t0 = time.monotonic()
    ack = await asyncio.wait_for(await sup.request("report"), 5)
    assert ack["event"] == "scan" and ack["trigger"] == "request"
    assert time.monotonic() - t0 >= FAST.report_grace * 0.9
    await stopped(sup, task)


async def test_unknown_command_error_is_protocol_error():
    sup, rec, task = await started("--fake-misread", timing=DEAF)
    assert await asyncio.wait_for(await sup.request("scan"), 5) is None
    assert "Unknown control command" in rec.of("protocol-error")[0]["message"]
    assert sup.can_request
    await stopped(sup, task)


async def test_request_timeout():
    t = Timing(**{**FAST.__dict__, "request_timeout": 0.2})
    sup, rec, task = await started("--fake-delay", "1", timing=t)
    assert await asyncio.wait_for(await sup.request("scan"), 5) is None
    assert "no response" in rec.of("protocol-error")[0]["message"]
    await stopped(sup, task)


async def test_broken_pipe_is_an_exit():
    sup, rec, task = await started("--fake-close-stdin", timing=DEAF)
    await asyncio.sleep(0.2)                          # let fake fetter close its stdin
    assert await sup.request("scan") is None
    assert "cannot write" in rec.of("protocol-error")[0]["message"]
    await rec.wait(count("launch", 2))                # terminated, then restarted
    assert not rec.of("fetter-exit")[0]["expected"]
    await stopped(sup, task)


async def test_request_rejects_other_commands():
    sup, rec, task = await started()
    with pytest.raises(ValueError):
        await sup.request("stop")
    await stopped(sup, task)


async def test_request_when_not_running():
    sup = Supervisor(cmd(), Rec(), None, FAST)
    assert await sup.request("scan") is None


# stale fetter -----------------------------------------------------------------

def spawn(*argv):
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    threading.Thread(target=proc.wait, daemon=True).start()     # reap it when it ends
    time.sleep(0.3)
    return proc


def test_stop_stale_fetter(home):
    store = Store(home)
    proc = spawn(*cmd())
    store.update_state(fetter={"pid": proc.pid, "binary": str(FAKE)})
    rec = Rec()
    assert stop_stale(store, rec, timeout=3) == proc.pid
    proc.wait(timeout=5)
    assert rec.kinds() == ["stale-stop"]
    assert "fetter" not in store.read_state()


def test_stop_stale_leaves_other_process(home):
    store = Store(home)
    proc = spawn(sys.executable, "-c", "import time; time.sleep(30)")
    try:
        store.update_state(fetter={"pid": proc.pid, "binary": str(FAKE)})
        assert stop_stale(store, timeout=1) is None
        assert proc.poll() is None
        assert "fetter" not in store.read_state()
    finally:
        proc.kill()


def test_stop_stale_nothing_recorded(home):
    assert stop_stale(Store(home)) is None


# headless ---------------------------------------------------------------------

async def test_headless_logs_and_stops(home):
    out = []
    store = Store(home)
    h = Headless(cmd(), store, out=out.append, timing=FAST)
    task = asyncio.create_task(h.run())
    deadline = time.monotonic() + 10
    while not any("scan (start)" in line for line in out):
        assert time.monotonic() < deadline, out
        await asyncio.sleep(0.02)
    await h.supervisor.stop()
    assert await asyncio.wait_for(task, 10) == 0
    stored = [p.kind for p in store.iter_entries()]
    assert stored == ["launch", "start", "scan", "control", "fetter-exit"]
    assert len(out) == 5 and "fetter exited with 0" in out[-1]


async def test_stop_while_launching():
    rec = Rec()
    sup = Supervisor(cmd(), rec, None, FAST)
    task = asyncio.create_task(sup.run())
    await asyncio.sleep(0)                            # run() is inside create_subprocess_exec
    await sup.stop()
    await asyncio.wait_for(task, 10)
    assert sup.status == "stopped"
    assert rec.of("fetter-exit")[-1]["expected"]
    assert len(rec.of("launch")) <= 1
