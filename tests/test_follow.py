import asyncio
import json
import os
import time

from fetter_scope.supervisor import follow


def line(kind: str, n: int = 0) -> str:
    return json.dumps({"schema": 1, "event": kind, "time": {"secs": n, "nanos": 0}}) + "\n"


class Following:
    def __init__(self, path):
        self.entries, self.stop = [], asyncio.Event()
        self.task = asyncio.create_task(follow(path, self.entries.append, poll=0.02, stop=self.stop))

    def kinds(self):
        return [p.kind for p in self.entries]

    async def wait(self, n, timeout=5):
        deadline = time.monotonic() + timeout
        while len(self.entries) < n:
            assert time.monotonic() < deadline, self.kinds()
            await asyncio.sleep(0.02)

    async def close(self):
        self.stop.set()
        await asyncio.wait_for(self.task, 5)


async def test_follow_appended_file(tmp_path):
    f = tmp_path / "stream.jsonl"
    f.write_text(line("start") + line("scan"))
    fol = Following(f)
    await fol.wait(2)
    with open(f, "a") as fh:
        fh.write(line("report")[:10])              # a partial line is held back
        fh.flush()
        await asyncio.sleep(0.1)
        assert fol.kinds() == ["start", "scan"]
        fh.write(line("report")[10:])
    await fol.wait(3)
    assert fol.kinds() == ["start", "scan", "report"]
    await fol.close()


async def test_follow_file_created_later_and_truncated(tmp_path):
    f = tmp_path / "stream.jsonl"
    fol = Following(f)
    await asyncio.sleep(0.1)
    f.write_text(line("start") + line("scan"))
    await fol.wait(2)
    f.write_text(line("error"))                     # truncated and rewritten
    await fol.wait(3)
    assert fol.kinds() == ["start", "scan", "error"]
    await fol.close()


async def test_follow_replaced_file(tmp_path):
    f = tmp_path / "stream.jsonl"
    f.write_text(line("start"))
    fol = Following(f)
    await fol.wait(1)
    new = tmp_path / "new.jsonl"
    new.write_text(line("scan") + line("report"))
    os.replace(new, f)
    await fol.wait(3)
    assert fol.kinds() == ["start", "scan", "report"]
    await fol.close()


async def test_follow_events_directory(tmp_path):
    d = tmp_path / "events"
    d.mkdir()
    (d / "2026-11-15.jsonl").write_text(line("start", 1) + line("scan", 2))
    (d / "2026-11-16.jsonl").write_text(line("scan", 3))
    (d / "ignore.txt").write_text("x\n")
    fol = Following(d)
    await fol.wait(3)
    assert [p.event["time"]["secs"] for p in fol.entries] == [1, 2, 3]
    with open(d / "2026-11-16.jsonl", "a") as fh:
        fh.write(line("report", 4))
    (d / "2026-11-17.jsonl").write_text(line("scan", 5))
    await fol.wait(5)
    assert [p.event["time"]["secs"] for p in fol.entries] == [1, 2, 3, 4, 5]
    await fol.close()


async def test_follow_empty_directory(tmp_path):
    fol = Following(tmp_path)
    await asyncio.sleep(0.1)
    (tmp_path / "2026-11-16.jsonl").write_text(line("start"))
    await fol.wait(1)
    await fol.close()
