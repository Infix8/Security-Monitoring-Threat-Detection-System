from pathlib import Path

import pytest

from app import watcher


SAMPLE_FAILED = (
    "Oct  3 13:10:01 web01 sshd[1001]: Failed password for invalid user "
    "admin from 203.0.113.42 port 51234 ssh2\n"
)


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(watcher, "STATE_DIR", tmp_path / "state")
    return tmp_path / "state"


def _write(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text)


def test_watcher_processes_new_lines(tmp_path, state_dir):
    logfile = tmp_path / "auth.log"
    logfile.write_text("")  # create empty

    # First pass: nothing
    st1 = watcher.watch("auth", logfile, once=True)
    assert st1.lines_seen == 0

    # Append one failed line
    _write(logfile, SAMPLE_FAILED)
    st2 = watcher.watch("auth", logfile, once=True)
    assert st2.lines_seen == 1
    assert st2.lines_parsed == 1
    assert st2.events_inserted == 1

    # Second pass without appending: no new work
    st3 = watcher.watch("auth", logfile, once=True)
    assert st3.lines_seen == 0
    assert st3.events_inserted == 0


def test_watcher_deduplicates_on_restart(tmp_path, state_dir):
    logfile = tmp_path / "auth.log"
    logfile.write_text(SAMPLE_FAILED)

    st1 = watcher.watch("auth", logfile, once=True)
    assert st1.events_inserted == 1

    # Wipe state so watcher forgets its offset, but keep the file
    for p in state_dir.glob("*.json"):
        p.unlink()

    st2 = watcher.watch("auth", logfile, once=True)
    # Re-parses the file, but DB-level dedup means 0 new event rows
    assert st2.lines_seen == 1
    assert st2.events_inserted == 0
    assert st2.events_skipped == 1


def test_watcher_detects_rotation(tmp_path, state_dir):
    logfile = tmp_path / "auth.log"
    logfile.write_text(SAMPLE_FAILED)
    watcher.watch("auth", logfile, once=True)

    # Simulate rotation: rename and create new file (different inode)
    rotated = tmp_path / "auth.log.1"
    logfile.rename(rotated)
    logfile.write_text(SAMPLE_FAILED)

    st = watcher.watch("auth", logfile, once=True)
    assert st.rotations == 1
    # Same content so events dedup to 0 new
    assert st.events_inserted == 0


def test_watcher_brute_force_fires(tmp_path, state_dir):
    logfile = tmp_path / "auth.log"
    logfile.write_text("")
    for i in range(6):
        _write(
            logfile,
            f"Oct  3 13:10:{i:02d} web01 sshd[100{i}]: Failed password for "
            f"root from 1.2.3.4 port {5000+i} ssh2\n",
        )

    st = watcher.watch("auth", logfile, once=True)
    assert st.events_inserted == 6
    assert st.findings >= 1
    assert st.threats_inserted >= 1
