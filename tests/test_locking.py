from __future__ import annotations

import multiprocessing
from pathlib import Path

from app.locking import InterProcessRunLock


def _hold_lock(database_path: str, ready, release) -> None:
    lock = InterProcessRunLock(Path(database_path))
    acquired = lock.acquire()
    ready.put(acquired)
    if acquired:
        release.wait(10)
        lock.release()


def test_run_lock_is_exclusive_across_processes_and_released_on_exit(tmp_path):
    database = str(tmp_path / "shared.sqlite3")
    context = multiprocessing.get_context("spawn")
    ready = context.Queue()
    release = context.Event()
    process = context.Process(target=_hold_lock, args=(database, ready, release))
    process.start()
    assert ready.get(timeout=15) is True

    contender = InterProcessRunLock(Path(database))
    assert contender.acquire() is False

    release.set()
    process.join(timeout=15)
    assert process.is_alive() is False
    assert process.exitcode == 0
    assert contender.acquire() is True
    contender.release()


def test_run_lock_is_released_when_owner_process_terminates(tmp_path):
    database = str(tmp_path / "crash.sqlite3")
    context = multiprocessing.get_context("spawn")
    ready = context.Queue()
    release = context.Event()
    process = context.Process(target=_hold_lock, args=(database, ready, release))
    process.start()
    assert ready.get(timeout=15) is True
    process.terminate()
    process.join(timeout=15)

    recovered = InterProcessRunLock(Path(database))
    assert recovered.acquire() is True
    recovered.release()
