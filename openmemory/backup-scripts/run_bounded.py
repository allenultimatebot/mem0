#!/usr/bin/env python3
import os
import signal
import subprocess
import sys


seconds = float(sys.argv[1])
command = sys.argv[2:]
try:
    os.fstat(3)
    pass_fds = (3,)
except OSError:
    pass_fds = ()
process = subprocess.Popen(command, start_new_session=True, pass_fds=pass_fds)
active = os.environ.get("OPENMEMORY_ACTIVE_CHILD_FILE")
if active:
    temporary = f"{active}.tmp.{os.getpid()}.{process.pid}"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(f"pid={process.pid}\npgid={os.getpgid(process.pid)}\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, active)


def clear_active():
    if active:
        try:
            with open(active, encoding="utf-8") as handle:
                if handle.read().splitlines()[:1] != [f"pid={process.pid}"]:
                    return
            os.unlink(active)
        except FileNotFoundError:
            pass


def terminate(signum, _frame):
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    clear_active()
    raise SystemExit(128 + signum)


signal.signal(signal.SIGTERM, terminate)
signal.signal(signal.SIGINT, terminate)
try:
    process.wait(timeout=seconds)
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    clear_active()
    raise SystemExit(124)
finally:
    clear_active()
raise SystemExit(process.returncode)
