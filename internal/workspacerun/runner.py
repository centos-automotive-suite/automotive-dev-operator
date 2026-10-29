"""Durable workspace runs. Invoked through pod exec; no daemon is required."""

import collections
import contextlib
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(sys.argv[1])
WORKDIR = sys.argv[2]
LIVE = ("Starting", "Running", "Cancelling")
TERMINAL = ("Succeeded", "Failed", "Cancelled", "Interrupted", "TimedOut")
TOMBSTONE_TTL = 24 * 60 * 60
# All versions preserve the envelope: id, version, status, startedAt, live
# supervisor pid/identity, and terminal finishedAt. LIVE/TERMINAL and identity's
# encoding are fixed; new details belong in the versioned payload. Terminal
# statuses never become live again. Keep state.json, root-then-run flock order,
# atomic writes, and exclusive ownership of each run directory compatible.
# Bump for incompatible payloads, retaining readers for older versions. Existing
# supervisors keep writing their original format; older readers never rewrite it.
RECORD_VERSION = 1


class RunError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] == "Z":
            return None
        return [Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                os.readlink(f"/proc/{pid}/ns/pid"), fields[19]]
    except FileNotFoundError:
        return None


def require_supported(state):
    if state["version"] != RECORD_VERSION:
        raise RunError(409, f"run {state['id']} uses newer record format {state['version']}; this operation requires a compatible operator")


def save(directory, state):
    require_supported(state)
    with (directory / "state.tmp").open("w") as stream:
        json.dump(state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(directory / "state.tmp", directory / "state.json")
    # Persist the rename as well as the contents before acknowledging a save.
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextlib.contextmanager
def locked(directory):
    try:
        stream = (directory / "lock").open("a")
    except FileNotFoundError:
        raise missing_run(directory) from None
    except OSError as error:
        raise RunError(422, f"unreadable run record {directory.name}: {error}") from None
    with stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield stream


def missing_run(directory):
    if tombstoned(directory.name):
        return RunError(410, "run was deleted or expired; use a new ID for a new command")
    return RunError(404, "run not found")


def envelope(directory, state):
    if state["id"] != directory.name:
        raise ValueError("invalid record identity")
    if state["status"] not in LIVE + TERMINAL:
        raise ValueError("invalid status")
    keys = ("id", "version", "status", "startedAt")
    for key in ("startedAt",) + (("finishedAt",) if state["status"] in TERMINAL else ()):
        if datetime.datetime.fromisoformat(state[key]).tzinfo is None:
            raise ValueError(f"{key} must include a timezone")
    if state["status"] in LIVE:
        if type(state["pid"]) is not int or state["pid"] <= 0:
            raise ValueError("invalid supervisor PID")
        if not isinstance(state["identity"], list) or len(state["identity"]) != 3 or not all(isinstance(value, str) for value in state["identity"]):
            raise ValueError("invalid supervisor identity")
        keys += ("pid", "identity")
    else:
        keys += ("finishedAt",)
    return {key: state[key] for key in keys}


def uncertain_newer_record(directory, version, error):
    # Preserve visibility without allowing an ambiguous envelope to authorize
    # auto-pause, deletion, or retention. This projection is never written back.
    return dict(id=directory.name, version=version, status="Unknown",
                message=f"Cannot determine run activity from its envelope: {error}")


def read_state(directory):
    version = None
    try:
        state = json.loads((directory / "state.json").read_text())
        if not isinstance(state, dict):
            raise ValueError("invalid record")
        # Unversioned records from before release have the version 1 layout.
        version = state.setdefault("version", 1)
        if type(version) is not int or version < 1:
            raise ValueError("invalid record version")
        common = envelope(directory, state)
        if version != RECORD_VERSION:
            state = common
        else:
            if not isinstance(state["command"], str):
                raise ValueError("invalid command")
            for key, minimum in (("maxLogBytes", 1), ("timeoutSeconds", 1), ("requestedTimeoutSeconds", 0)):
                if type(state[key]) is not int or state[key] < minimum:
                    raise ValueError(f"invalid {key}")
            if state["status"] in TERMINAL and state["status"] != "Interrupted" and "exitCode" not in state:
                raise ValueError("missing exit code")
            if "exitCode" in state and (type(state["exitCode"]) is not int or not 0 <= state["exitCode"] <= 255):
                raise ValueError("invalid exit code")
            if not isinstance(state.get("message", ""), str):
                raise ValueError("invalid message")
            if type(state.get("logsEvicted", False)) is not bool:
                raise ValueError("invalid logsEvicted")
            if state.get("logsEvicted") and (state["status"] in LIVE or type(state["logBytes"]) is not int or state["logBytes"] < 0):
                raise ValueError("invalid evicted log offsets")
    except FileNotFoundError:
        raise missing_run(directory) from None
    except (ValueError, KeyError, TypeError, OSError) as error:
        if type(version) is int and version > RECORD_VERSION:
            return uncertain_newer_record(directory, version, error)
        raise RunError(422, f"unreadable run record {directory.name}: {error}") from None
    try:
        stopped = state["status"] in LIVE and identity(state["pid"]) != state["identity"]
        if stopped:
            finished_at = now()
            if version != RECORD_VERSION:
                # A read-only projection needs a stable retention timestamp.
                # The last record write is a proxy, not the exact crash time.
                finished_at = datetime.datetime.fromtimestamp(
                    (directory / "state.json").stat().st_mtime, datetime.timezone.utc).isoformat()
    except OSError as error:
        if version != RECORD_VERSION:
            return uncertain_newer_record(directory, version, error)
        raise
    if stopped:
        state.update(status="Interrupted", finishedAt=finished_at,
                     message="The workspace container or run supervisor stopped before recording an exit code")
        # Reads must remain usable when the volume cannot persist recovery.
        # Launch and cancellation still require their explicit saves to succeed.
        if version == RECORD_VERSION:
            with contextlib.suppress(OSError):
                save(directory, state)
    return state


def segments(directory):
    files = sorted((directory / "logs").glob("*.log"))
    return [(int(file.stem), file.stat().st_size, file) for file in files]


def log_window(directory, state):
    require_supported(state)
    if state.get("logsEvicted"):
        return state["logBytes"], state["logBytes"], []
    chunks = segments(directory)
    end = chunks[-1][0] + chunks[-1][1] if chunks else 0
    return max(0, end - state["maxLogBytes"]), end, chunks


def public(directory, state):
    private = ("version", "pid", "identity", "maxLogBytes", "requestedTimeoutSeconds")
    result = {key: value for key, value in state.items() if key not in private}
    if state["version"] != RECORD_VERSION:
        note = f"Run uses newer record format {state['version']}; only lifecycle metadata is available. Command, exit code, logs and cancellation require a compatible operator."
        message = result.get("message", "").rstrip(". ")
        result["message"] = message + ". " + note if message else note
        return result
    start, end, _ = log_window(directory, state)
    result.update(logBytes=end, logStartOffset=start, logTruncated=start > 0,
                  logsEvicted=state.get("logsEvicted", False))
    return result


def read_log(directory, state, offset, length=1024 * 1024):
    start, end, chunks = log_window(directory, state)
    if offset < 0 or offset > end:
        raise RunError(416, "offset exceeds available log bytes")
    offset = max(offset, start)
    data = bytearray()
    for first, size, file in chunks:
        if first + size <= offset:
            continue
        with file.open("rb") as stream:
            stream.seek(offset - first)
            block = stream.read(min(length - len(data), first + size - offset))
        data.extend(block)
        offset += len(block)
        if len(data) == length:
            break
    return offset - len(data), bytes(data)


class LogWriter:
    """Append bounded segments without copying the entire retained tail.

    Offsets are encoded in segment names, so a supervisor crash cannot leave a
    stale byte counter. One leading segment may retain an inaccessible prefix;
    physical overhead is bounded by one segment (at most 1 MiB).
    """
    def __init__(self, directory, limit):
        self.directory = directory / "logs"
        self.directory.mkdir(exist_ok=True)
        self.limit = limit
        self.chunk_size = min(1024 * 1024, limit)
        self.chunks = collections.deque()
        self.position = 0
        self.output = None

    def write(self, data):
        while data:
            first = self.position // self.chunk_size * self.chunk_size
            file = self.directory / f"{first:020d}.log"
            count = min(len(data), self.chunk_size - (self.position - first))
            if not self.chunks or self.chunks[-1][0] != first:
                if self.output is not None:
                    self.output.close()
                self.output = file.open("ab", buffering=0)
                self.chunks.append((first, file))
            count = self.output.write(data[:count])
            if count == 0:
                raise OSError("log write made no progress")
            self.position += count
            data = data[count:]
            while self.chunks and self.chunks[0][0] + self.chunk_size <= self.position - self.limit:
                self.chunks.popleft()[1].unlink()

    def close(self):
        if self.output is not None:
            self.output.close()
        # Trim the partial leading segment once, on completion, so completed
        # logs fit the budget even when the per-log cap equals that budget.
        start = max(0, self.position - self.limit)
        if self.chunks and self.chunks[0][0] < start:
            first, file = self.chunks[0]
            tail = file.read_bytes()[start - first:]
            (self.directory / f"{start:020d}.log").write_bytes(tail)
            file.unlink()


def kill_group(process, sig):
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def pump(directory, process, options):
    writer = LogWriter(directory, options["maxLogBytes"])
    deadline = time.monotonic() + options["timeoutSeconds"]
    try:
        with selectors.DefaultSelector() as selector:
            return pump_output(directory, process, writer, selector, deadline)
    finally:
        process.stdout.close()
        with locked(directory):
            writer.close()


def pump_output(directory, process, writer, selector, deadline):
    escalation = reason = drain_deadline = None
    pipe_open = True
    next_check = 0
    selector.register(process.stdout, selectors.EVENT_READ)
    while pipe_open or process.poll() is None:
        for key, _ in selector.select(timeout=max(0, next_check - time.monotonic())):
            data = os.read(key.fd, 65536)
            if data:
                with locked(directory):
                    writer.write(data)
            else:
                selector.unregister(key.fileobj)
                pipe_open = False
        if time.monotonic() >= next_check:
            with locked(directory):
                state = read_state(directory)
                if reason is None and state["status"] == "Cancelling":
                    reason = "cancel"
                if reason is None and time.monotonic() >= deadline:
                    reason = "timeout"
                    state.update(status="Cancelling", message=f"Run timed out after {state['timeoutSeconds']} seconds")
                    save(directory, state)
            next_check = time.monotonic() + 0.1
        if reason is not None and escalation is None:
            escalation = time.monotonic() + 5
            kill_group(process, signal.SIGTERM)
        if escalation is not None and time.monotonic() >= escalation:
            kill_group(process, signal.SIGKILL)
        if process.poll() is not None and drain_deadline is None:
            # Background descendants must stop producing output before the
            # final result is recorded. PID 1's init reaps orphaned children.
            kill_group(process, signal.SIGKILL)
            drain_deadline = time.monotonic() + 1
        if drain_deadline is not None and time.monotonic() >= drain_deadline:
            # A descendant that escaped the process group may still hold
            # the pipe open. It must not keep the supervisor alive forever.
            break
    return reason


def supervise(directory, command, options):
    process = None
    try:
        with locked(directory):
            state = read_state(directory)
            if state["status"] == "Cancelling":
                state.update(status="Cancelled", exitCode=130, finishedAt=now())
                save(directory, state)
                return
            process = subprocess.Popen(["/bin/sh", "-c", command], cwd=WORKDIR,
                                       start_new_session=True, close_fds=True,
                                       umask=ORIGINAL_UMASK, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)
        reason = pump(directory, process, options)
        code = process.returncode
        if code < 0:
            code = 128 - code
        with locked(directory):
            state = read_state(directory)
            cancelled = reason == "cancel" or state["status"] == "Cancelling"
            status = "Cancelled" if cancelled else ("Succeeded" if code == 0 else "Failed")
            if reason == "timeout":
                status, code = "TimedOut", 124
            state.update(status=status, exitCode=code, finishedAt=now())
            save(directory, state)
    except BaseException as error:
        if process is not None:
            kill_group(process, signal.SIGKILL)
            process.wait()
        with locked(directory):
            state = read_state(directory)
            state.update(status="Failed", exitCode=127, finishedAt=now(), message=str(error))
            save(directory, state)
    finally:
        # No run lock is held while taking the collection lock: all collection
        # operations lock ROOT before individual runs.
        with locked(ROOT):
            prune(options)


def tombstoned(run_id):
    try:
        return (ROOT / ".deleted" / run_id).stat().st_mtime >= time.time() - TOMBSTONE_TTL
    except FileNotFoundError:
        return False


def erase(directory):
    try:
        state = read_state(directory)
    except RunError as error:
        if error.code not in (404, 422):
            raise
    else:
        if state["status"] not in TERMINAL:
            raise RunError(409, "run is live or its activity is unknown; wait until it is confirmed stopped before deleting it")
    tombstones = ROOT / ".deleted"
    tombstones.mkdir(exist_ok=True)
    (tombstones / directory.name).touch()
    shutil.rmtree(directory)


def evict_logs(directory):
    state = read_state(directory)
    require_supported(state)
    if state["status"] in LIVE:
        return
    _, end, _ = log_window(directory, state)
    # Record the absolute end before removing segments. A crash during removal
    # still leaves a readable result and a truthful empty retained window.
    state.update(logsEvicted=True, logBytes=end)
    save(directory, state)
    if (directory / "logs").exists():
        shutil.rmtree(directory / "logs")


def visible_runs():
    for directory in ROOT.glob("*/"):
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", directory.name):
            continue
        if not (directory / "state.json").is_file():
            continue
        try:
            with locked(directory):
                yield directory, read_state(directory)
        except RunError as error:
            if error.code not in (404, 410, 422):
                raise


def prune(options):
    for tombstone in (ROOT / ".deleted").glob("*"):
        if tombstone.stat().st_mtime < time.time() - TOMBSTONE_TTL:
            tombstone.unlink()
    terminal = []
    cutoff = time.time() - options["retentionSeconds"]
    for directory, state in visible_runs():
        if state["status"] not in TERMINAL:
            continue
        finished = datetime.datetime.fromisoformat(state["finishedAt"]).timestamp()
        terminal.append((finished, directory))
    retained = []
    total = 0
    excess = len(terminal) - options["maxRecords"]
    for index, (finished, directory) in enumerate(sorted(terminal)):
        with locked(directory):
            if finished < cutoff or index < excess:
                erase(directory)
            else:
                state = read_state(directory)
                if state["version"] != RECORD_VERSION:
                    continue  # Unknown log layouts cannot participate in budget eviction.
                _, _, chunks = log_window(directory, state)
                size = sum(chunk[1] for chunk in chunks)
                retained.append((directory, size))
                total += size
    for directory, size in retained:
        if total <= options["completedLogBudgetBytes"]:
            break
        with locked(directory):
            evict_logs(directory)
        total -= size


def launch(directory, run_id, command, options, collection_lock):
    directory.mkdir(parents=True, exist_ok=True)
    with locked(directory) as lock:
        if (directory / "state.json").exists():
            state = read_state(directory)
            require_supported(state)
            if state["command"] != command or state["requestedTimeoutSeconds"] != options["requestedTimeoutSeconds"]:
                raise RunError(409, "run ID already belongs to a different command or timeout")
            return public(directory, state)
        (directory / "logs").mkdir(exist_ok=True)
        state = dict(version=RECORD_VERSION, id=run_id, command=command, status="Starting", startedAt=now(),
                     pid=os.getpid(), identity=identity(os.getpid()),
                     timeoutSeconds=options["timeoutSeconds"], maxLogBytes=options["maxLogBytes"],
                     requestedTimeoutSeconds=options["requestedTimeoutSeconds"])
        save(directory, state)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                try:
                    os.close(read_fd)
                    os.setsid()
                    # The supervisor owns no exec connection descriptors. Command
                    # output is pumped separately into bounded persistent segments.
                    with open(os.devnull, "r+b", buffering=0) as null:
                        for fd in (0, 1, 2):
                            os.dup2(null.fileno(), fd)
                    state.update(status="Running", pid=os.getpid(), identity=identity(os.getpid()))
                    save(directory, state)
                except BaseException as error:
                    # The launcher still holds the run lock and records the cause.
                    detail = f"{type(error).__name__}: {error}"
                    os.write(write_fd, b"E" + detail.encode("utf-8", "replace")[:4000])
                    os._exit(1)
                os.write(write_fd, b"1")
                os.close(write_fd)
                lock.close()
                collection_lock.close()
                supervise(directory, command, options)
            finally:
                os._exit(0)
        os.close(write_fd)
        try:
            # Replies up to PIPE_BUF bytes arrive in a single atomic write.
            reply = os.read(read_fd, 4096)
        finally:
            os.close(read_fd)
        if reply != b"1":
            # The command never started, so it must not read as interrupted.
            # A retry with the same ID returns this result instead of a 500.
            detail = reply[1:].decode("utf-8", "replace") if reply[:1] == b"E" else "it exited before acknowledging"
            state.update(status="Failed", exitCode=127, finishedAt=now(),
                         message=f"Run supervisor failed to start: {detail}")
            # A full volume is the likely cause, so this save may fail as well.
            # The response still reports the cause from memory.
            with contextlib.suppress(OSError):
                save(directory, state)
            return public(directory, state)
        return public(directory, read_state(directory))


def active_runs():
    return any(state["status"] not in TERMINAL for _, state in visible_runs())


def stream_log(directory, offset, end, follow, duration):
    deadline = time.monotonic() + duration
    result = {}
    while True:
        with locked(directory):
            state = read_state(directory)
            require_supported(state)
            run = public(directory, state)
            # Never silently skip bytes mid-response. Reconnect with a new
            # X-Log-Offset header when rotation overtakes a slow reader.
            if offset < run["logStartOffset"]:
                result = {"run": run, "error": "log tail advanced; reconnect to resume", "code": 409}
                break
            actual, data = read_log(directory, state, offset)
            if not follow:
                data = data[:max(0, end - actual)]
        if data:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            offset += len(data)
        result = {"run": run}
        if (not follow and offset >= end) or (state["status"] not in LIVE and offset >= run["logBytes"]):
            break
        if time.monotonic() >= deadline:
            break
        if not data:
            time.sleep(0.2)
    result["nextOffset"] = offset
    print(json.dumps(result), file=sys.stderr, flush=True)


def main():
    global ORIGINAL_UMASK
    ORIGINAL_UMASK = os.umask(0o077)
    action = sys.argv[3]
    if action not in ("active", "list", "create", "get", "log-info", "delete", "stream", "cancel"):
        raise RunError(400, "unknown runner action")
    if action == "active":
        return {"active": active_runs()}
    if action == "list":
        runs = [public(directory, state) for directory, state in visible_runs()]
        runs.sort(key=lambda run: (datetime.datetime.fromisoformat(run["startedAt"]).timestamp() if "startedAt" in run else float("-inf"), run["id"]), reverse=True)
        offset, limit = int(sys.argv[4]), int(sys.argv[5])
        return {"runs": runs[offset:offset + limit]}
    run_id = sys.argv[4]
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", run_id):
        raise RunError(400, "invalid run ID")
    directory = ROOT / run_id
    if action == "create":
        options = json.loads(sys.argv[6])
        ROOT.mkdir(parents=True, exist_ok=True)
        with locked(ROOT) as collection_lock:
            if tombstoned(run_id):
                raise RunError(410, "run was deleted or expired; use a new ID for a new command")
            if not (directory / "state.json").exists():
                prune(options)
            return {"run": launch(directory, run_id, sys.argv[5], options, collection_lock)}
    if action == "delete":
        with locked(ROOT):
            if tombstoned(run_id) and not directory.is_dir():
                return {}
            with locked(directory):
                erase(directory)
        return {}
    if not directory.is_dir():
        raise missing_run(directory)
    if action == "stream":
        stream_log(directory, int(sys.argv[5]), int(sys.argv[6]), sys.argv[7] == "true", float(sys.argv[8]))
        return None
    with locked(directory):
        state = read_state(directory)
        if action in ("cancel", "log-info"):
            require_supported(state)
        if action == "cancel" and state["status"] in LIVE:
            state["status"] = "Cancelling"
            save(directory, state)
        return {"run": public(directory, state)}


try:
    result = main()
    if result is not None:
        print(json.dumps(result), flush=True)
except RunError as error:
    output = sys.stderr if sys.argv[3] == "stream" else sys.stdout
    print(json.dumps({"code": error.code, "error": str(error)}), file=output, flush=True)
except Exception as error:
    output = sys.stderr if sys.argv[3] == "stream" else sys.stdout
    print(json.dumps({"code": 500, "error": f"{type(error).__name__}: {error}"}), file=output, flush=True)
