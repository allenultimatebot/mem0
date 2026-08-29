#!/usr/bin/env python3
"""Coordinator-loss safety net for isolated Mem0 candidate runs.

While the coordinator lives this records the process groups and process ids of
the detached operations it starts. When the coordinator disappears the recorded
operations are terminated and verified gone, every candidate container, network,
volume and image is checked for this run's label, the candidate is torn down,
candidate images are removed, and the private run artifacts are always deleted.
Ambiguous ownership stops Docker cleanup instead of guessing.
"""
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

run_dir, project, run_id, context, docker_host, parent_pid = sys.argv[1:7]
run_dir = pathlib.Path(run_dir).resolve()
parent_pid = int(parent_pid)

LABEL = "com.ultimatesup.openmemory.candidate"
DOCKER_TIMEOUT = 30
PS_TIMEOUT = 10
PRIVATE_ARTIFACTS = ("source", "wheelhouse", "clone", "input", "build", "compose.yml", "operation.pgid")
CANDIDATE_IMAGES = (f"{project}-api:verified", f"{project}-egress:verified")
marker_argument = sys.argv[7] if len(sys.argv) > 7 else os.environ.get("OPENMEMORY_WATCHDOG_OPERATION_MARKER", "")
OPERATION_MARKER = pathlib.Path(marker_argument) if marker_argument else run_dir / "operation.pgid"
if not OPERATION_MARKER.is_absolute():
    OPERATION_MARKER = run_dir / OPERATION_MARKER
RECOVERY_REPORT = run_dir / "watchdog-recovery.json"

PROTECTED_PGIDS = {0, os.getpgrp()}
try:
    PROTECTED_PGIDS.add(os.getpgid(parent_pid))
except OSError:
    pass

tracked_pgids = set()
tracked_pids = set()
marker_ambiguous = False
stopping = False


def stop(_signum, _frame):
    global stopping
    stopping = True


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)


def bounded(argv, environment, timeout):
    try:
        process = subprocess.Popen(
            argv,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
    except OSError:
        return None
    try:
        stdout, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        process.communicate()
        return None
    return stdout if process.returncode == 0 else None


def docker(*args):
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "")}
    if context:
        environment["DOCKER_CONTEXT"] = context
    if docker_host:
        environment["DOCKER_HOST"] = docker_host
    return bounded(["docker", "--config", str(pathlib.Path.home() / ".docker"), *args], environment, DOCKER_TIMEOUT)


def process_table():
    output = bounded(["/bin/ps", "-Ao", "pid=,ppid=,pgid="], {"PATH": "/usr/bin:/bin"}, PS_TIMEOUT)
    if output is None:
        return None
    rows = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 3 and all(field.isdigit() for field in fields):
            rows.append(tuple(int(field) for field in fields))
    return rows


def record_operations():
    global marker_ambiguous
    if OPERATION_MARKER.parent != run_dir:
        marker_ambiguous = True
    if OPERATION_MARKER.is_symlink() or (OPERATION_MARKER.exists() and not OPERATION_MARKER.is_file()):
        marker_ambiguous = True
    rows = process_table()
    if rows is None:
        return
    marker = None
    if OPERATION_MARKER.is_file() and not OPERATION_MARKER.is_symlink():
        marker_text = ""
        try:
            marker_text = OPERATION_MARKER.read_text(encoding="utf-8").strip()
            marker = json.loads(marker_text)
        except (OSError, TypeError, ValueError):
            marker = int(marker_text) if marker_text.isdigit() else None
            if marker is None:
                marker_ambiguous = True
        else:
            if isinstance(marker, dict):
                if marker.get("run_id", run_id) != run_id:
                    marker_ambiguous = True
                marker_pid = marker.get("pid")
                marker_pgid = marker.get("pgid")
                valid_marker = isinstance(marker_pid, int) and marker_pid > 0 and (
                    marker_pgid is None or (isinstance(marker_pgid, int) and marker_pgid > 0)
                )
                marker_row = next((row for row in rows if row[0] == marker_pid), None)
                if not valid_marker or marker_row is None or (marker_pgid is not None and marker_row[2] != marker_pgid):
                    marker_ambiguous = True
                else:
                    tracked_pids.add(marker_pid)
                    if marker_row[2] not in PROTECTED_PGIDS:
                        tracked_pgids.add(marker_row[2])
            elif isinstance(marker, int) and marker > 0:
                marker_row = next((row for row in rows if row[0] == marker), None)
                if marker_row is None:
                    marker_ambiguous = True
                else:
                    tracked_pids.add(marker)
                    if marker_row[2] not in PROTECTED_PGIDS:
                        tracked_pgids.add(marker_row[2])
            else:
                marker_ambiguous = True
    children = {}
    for pid, ppid, pgid in rows:
        children.setdefault(ppid, []).append((pid, pgid))
    stack, seen = [parent_pid], set()
    while stack:
        for pid, pgid in children.get(stack.pop(), ()):
            if pid in seen:
                continue
            seen.add(pid)
            stack.append(pid)
            if pgid in PROTECTED_PGIDS:
                if pid != os.getpid():
                    tracked_pids.add(pid)
            else:
                tracked_pgids.add(pgid)


def live_operations():
    rows = process_table()
    if rows is None:
        return None
    return {pid for pid, _ppid, pgid in rows if pgid in tracked_pgids or pid in tracked_pids}


def terminate_operations():
    if marker_ambiguous:
        return False
    if not tracked_pgids and not tracked_pids:
        return True
    for number in (signal.SIGTERM, signal.SIGKILL):
        for pgid in sorted(tracked_pgids):
            try:
                os.killpg(pgid, number)
            except OSError:
                pass
        for pid in sorted(tracked_pids):
            try:
                os.kill(pid, number)
            except OSError:
                pass
        for _attempt in range(10):
            live = live_operations()
            if live is not None and not live:
                return True
            time.sleep(0.5)
    live = live_operations()
    return live is not None and not live


def ownership_consistent(kind, selector):
    everything = docker(*kind, *selector)
    owned = docker(*kind, *selector, "--filter", f"label={LABEL}={run_id}")
    if everything is None or owned is None:
        return False
    return set(everything.split()) == set(owned.split())


def candidate_resources_owned():
    if not ownership_consistent(("ps", "-aq"), ("--filter", f"label=com.docker.compose.project={project}")):
        return False
    for kind in (("network", "ls", "-q"), ("volume", "ls", "-q")):
        if not ownership_consistent(kind, ("--filter", f"name={project}-")):
            return False
    image_tags = docker("image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter", f"label={LABEL}={run_id}")
    if image_tags is None or set(image_tags.split()) - set(CANDIDATE_IMAGES):
        return False
    return all(ownership_consistent(("image", "ls", "-q"), ("--filter", f"reference={image}")) for image in CANDIDATE_IMAGES)


def remove_candidate_images():
    failures = []
    for image in CANDIDATE_IMAGES:
        all_ids = docker("image", "ls", "-q", "--no-trunc", "--filter", f"reference={image}")
        owned_ids = docker(
            "image", "ls", "-q", "--no-trunc", "--filter", f"reference={image}", "--filter", f"label={LABEL}={run_id}"
        )
        if all_ids is None or owned_ids is None:
            failures.append(f"candidate image {image} ownership could not be confirmed")
            continue
        all_ids = set(all_ids.split())
        owned_ids = set(owned_ids.split())
        if all_ids != owned_ids:
            failures.append(f"candidate image {image} ownership changed")
            continue
        for image_id in sorted(owned_ids):
            label = docker("image", "inspect", "-f", '{{index .Config.Labels "com.ultimatesup.openmemory.candidate"}}', image_id)
            tags = docker("image", "inspect", "-f", "{{json .RepoTags}}", image_id)
            if label != run_id or tags is None:
                failures.append(f"candidate image {image_id} ownership could not be confirmed")
                continue
            try:
                image_tags = json.loads(tags)
            except (TypeError, ValueError):
                failures.append(f"candidate image {image_id} tags could not be confirmed")
                continue
            if image_tags and any(tag not in CANDIDATE_IMAGES for tag in image_tags):
                failures.append(f"candidate image {image_id} has an unexpected tag")
                continue
            if docker("image", "rm", image_id) is None:
                failures.append(f"candidate image {image_id} removal failed")
    return failures


def remove_private_artifacts():
    failures = []
    targets = [run_dir / name for name in PRIVATE_ARTIFACTS]
    if OPERATION_MARKER.parent == run_dir and OPERATION_MARKER not in targets:
        targets.append(OPERATION_MARKER)
    for target in targets:
        try:
            if target.is_symlink() or (target.exists() and not target.is_dir()):
                target.unlink()
            elif target.is_dir():
                shutil.rmtree(target)
        except OSError:
            failures.append(f"private artifact {target.name} could not be removed")
        if target.exists() or target.is_symlink():
            failures.append(f"private artifact {target.name} still present")
    return failures


def write_report(failures):
    report = {
        "schema": 1,
        "run_id": run_id,
        "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "recovered": not failures,
        "tracked_pgids": sorted(tracked_pgids),
        "tracked_pids": sorted(tracked_pids),
        "failures": failures,
    }
    try:
        RECOVERY_REPORT.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        RECOVERY_REPORT.chmod(0o600)
    except OSError:
        pass


def cleanup():
    failures = []
    if not terminate_operations():
        failures.append("candidate operation process group could not be terminated and verified")
    compose = run_dir / "compose.yml"
    if not failures:
        if candidate_resources_owned():
            if compose.is_file() and not compose.is_symlink():
                down = docker(
                    "compose",
                    "--project-directory",
                    str(run_dir),
                    "--file",
                    str(compose),
                    "--project-name",
                    project,
                    "down",
                    "--volumes",
                    "--remove-orphans",
                )
                if down is None:
                    failures.append("candidate compose teardown failed")
            failures.extend(remove_candidate_images())
        else:
            failures.append("candidate resource ownership is ambiguous; docker cleanup skipped")
    failures.extend(remove_private_artifacts())
    write_report(failures)


while not stopping:
    record_operations()
    try:
        os.kill(parent_pid, 0)
    except OSError:
        time.sleep(1)
        record_operations()
        cleanup()
        break
    time.sleep(1)
