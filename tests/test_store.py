import json
from datetime import datetime

from fetter_scope.events import own, parse_line
from fetter_scope.store import Store


def ts(s: str) -> float:
    return datetime.fromisoformat(s).timestamp()


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def test_append_daily_files(home):
    clock = Clock(ts("2026-11-15T23:59:00"))
    store = Store(home, now=clock)
    store.append(own("launch", now=clock.t, pid=1))
    clock.t = ts("2026-11-16T00:01:00")
    store.append(parse_line('{"schema":1,"event":"scan","time":{"secs":%d,"nanos":0}}' % clock.t))
    store.append(own("stderr", now=clock.t, line="multi\nline"))
    store.close()
    files = store.event_files()
    assert [f.name for f in files] == ["2026-11-15.jsonl", "2026-11-16.jsonl"]
    assert len(files[1].read_text().splitlines()) == 2
    assert [p.kind for p in store.iter_entries()] == ["launch", "scan", "stderr"]
    assert [p.kind for p in store.iter_entries(since=ts("2026-11-16T00:00:00"))] == ["scan", "stderr"]


def test_raw_fetter_line_kept_verbatim(home):
    store = Store(home)
    line = '{"schema":1,"event":"report","time":{"secs":5,"nanos":0},"x":[1,2]}'
    store.append(parse_line(line))
    store.close()
    assert store.event_files()[0].read_text() == line + "\n"


def test_iter_keeps_entries_without_time(home):
    store = Store(home, now=Clock(ts("2026-11-16T12:00:00")))
    store.append(parse_line('{"event":"odd"}'))
    store.close()
    assert [p.kind for p in store.iter_entries(since=ts("2026-11-16T11:00:00"))] == ["odd"]


def test_prune(home):
    home.events.mkdir(parents=True)
    for day in ("2026-08-17", "2026-08-18", "2026-11-16", "notes"):
        (home.events / f"{day}.jsonl").write_text("")
    store = Store(home, now=Clock(ts("2026-11-16T12:00:00")))
    assert store.prune(0) == []
    removed = store.prune(90)                      # cutoff 2026-08-18
    assert [p.name for p in removed] == ["2026-08-17.jsonl"]
    assert sorted(p.name for p in home.events.iterdir()) == \
        ["2026-08-18.jsonl", "2026-11-16.jsonl", "notes.jsonl"]


def test_state(home):
    store = Store(home)
    assert store.read_state() == {}
    store.update_state(fetter={"pid": 5}, last_digest=10)
    assert store.read_state() == {"fetter": {"pid": 5}, "last_digest": 10}
    store.update_state(fetter=None)
    assert json.loads(home.state.read_text()) == {"last_digest": 10}
    assert [p.name for p in home.root.iterdir()] == ["state.json"]   # no temp files left


def test_state_unreadable(home):
    home.root.mkdir(parents=True)
    home.state.write_text("{oops")
    assert Store(home).read_state() == {}
    home.state.write_text("[1]")
    assert Store(home).read_state() == {}
