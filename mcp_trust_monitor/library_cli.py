"""Installed, external-configuration CLI (also `python -m mcp_trust_monitor`).

The historical hackathon commands are separate: `python -m mcp_trust_monitor.historical_demo`.
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import enum
import json
import os
import sys
from pathlib import Path
from typing import Any


def _json(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {f.name: _json(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): _json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json(v) for v in value]
    return value


def load_config(path: Path, *, detector: bool = True):
    """Load JSON without resolving credential references or launching any server.

    Relative ``state_dir``, ``policy_path``, ``detector_binding``, server ``cwd`` and
    path-like executable commands resolve beside the config file; an omitted or null
    ``cwd`` uses that directory too. An optional ``detector_binding`` names the
    operator's binding JSON, so every owner of the state directory can declare the same
    policy/detector pair (REQ-DEC-06). ``detector=False`` skips reading it, for commands
    that only read the store and never activate a binding. Bare executable names retain caller PATH lookup. Arguments and
    credential references stay literal. The SDK's ``ServerConfig(cwd=None)`` still
    uses the process working directory when ``MonitorConfig`` is constructed.
    """
    from .config import ConfigurationError, MonitorConfig
    from .managed_client import ServerConfig
    from .policy import load_detector_binding
    path = path.expanduser().resolve()
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("configuration must be an object")
    allowed = {"state_dir", "policy_path", "servers", "client_id", "poll_interval",
               "timeout_seconds", "shutdown_timeout", "max_concurrency", "review_max_attempts",
               "detector_binding"}
    if set(raw) - allowed:
        raise ValueError("unknown configuration fields")
    def external(value: str) -> Path:
        if not isinstance(value, str) or not value:
            raise ValueError("paths must be nonempty strings")
        candidate = Path(value).expanduser()
        return candidate.resolve() if candidate.is_absolute() else (path.parent / candidate).resolve()
    servers = {}
    rows = raw.get("servers")
    if not isinstance(rows, list) or not rows:
        raise ValueError("servers must be a nonempty list")
    fields = {"server_id", "command", "args", "cwd", "env", "secret_env", "origin"}
    for row in rows:
        if not isinstance(row, dict) or set(row) - fields:
            raise ValueError("invalid server configuration fields")
        row = dict(row)
        if row.get("server_id") in servers:
            raise ValueError("duplicate server_id")
        command = row.get("command")
        if not isinstance(command, str) or not command or "\x00" in command:
            raise ConfigurationError("invalid server launch profile")
        # Resolve explicit paths before MonitorConfig can interpret them relative
        # to the caller. Keep absolute spellings and bare-name PATH lookup intact
        # (REQ-LIB-02, REQ-REV-04/05); never reinterpret argument/reference strings.
        if not Path(command).is_absolute() and (
                command in {".", ".."} or command.startswith("~")
                or os.sep in command or (os.altsep is not None and os.altsep in command)):
            # Preserve executable symlinks: dereferencing a venv interpreter would
            # launch its base Python without the configured environment's packages.
            row["command"] = os.path.abspath(path.parent / Path(command).expanduser())
        args = row.get("args", [])
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ValueError("server args must be a list of strings")
        row["args"] = tuple(args)
        # An omitted cwd must not depend on the caller's directory: that would launch
        # the same configured server against different relative data, under a
        # different launch identity, from different shells (REQ-LIB-02, REQ-REV-04).
        row["cwd"] = str(path.parent if row.get("cwd") is None else external(row["cwd"]))
        config = ServerConfig(**row)
        servers[config.server_id] = config
    binding = None
    if detector and raw.get("detector_binding") is not None:
        binding = load_detector_binding(external(raw["detector_binding"]))
    elif raw.get("detector_binding") is not None:
        external(raw["detector_binding"])  # still a well-formed path
    options = {k: v for k, v in raw.items()
               if k not in {"state_dir", "policy_path", "servers", "detector_binding"}}
    return MonitorConfig(state_dir=external(raw["state_dir"]),
                         policy_path=external(raw["policy_path"]), servers=servers,
                         detector=binding, **options)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Local, approval-bound MCP trust monitor")
    result.add_argument("--config", type=Path, required=True,
                        help="explicit JSON configuration; relative paths resolve beside this file")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("status", "catalog", "events"):
        command = commands.add_parser(name)
        command.add_argument("--server")
    command = commands.add_parser("export", help="versioned sanitized decision records; excludes raw text")
    command.add_argument("--pseudonym-key-file", type=Path,
                         help="read-only file whose exact bytes (at least 32 random bytes) key "
                              "pseudonyms that stay stable across exports; by default each export "
                              "uses a fresh random key that is never stored")
    for name in ("observe", "review"):
        command = commands.add_parser(name)
        command.add_argument("server")
    for name in ("approve", "restore"):
        command = commands.add_parser(name)
        command.add_argument("server")
        command.add_argument("--revision", required=True)
        command.add_argument("--generation", type=int, required=True)
        command.add_argument("--actor", default="operator-cli")
    command = commands.add_parser("quarantine")
    command.add_argument("server")
    command.add_argument("--reason", required=True)
    command.add_argument("--actor", default="operator-cli")
    command = commands.add_parser("call")
    command.add_argument("server")
    command.add_argument("tool")
    command.add_argument("--arguments", default="{}", help="JSON object")
    command.add_argument("--refresh", action="store_true", help="explicitly refresh an already approved server")
    command.add_argument("--selection", type=Path, help="JSON SelectionToken saved from this live session's catalog")
    commands.add_parser("monitor")
    command = commands.add_parser("serve")
    command.add_argument("--port", type=int, default=0)
    return result


async def run(args: argparse.Namespace) -> int:
    from .sdk import TrustMonitor
    read_only = args.command in {"status", "catalog", "events", "export"}
    # Read-only snapshots never activate a binding, so they do not need its file.
    config = load_config(args.config, detector=not read_only)
    if read_only:
        # A second writer is prohibited, but operator snapshots can coexist with it.
        # A different process has no fresh backing transport, so its catalog is empty.
        from .managed_client import trust_db_path
        from .trust_store import TrustStore
        key_file = getattr(args, "pseudonym_key_file", None) if args.command == "export" else None
        # Read only; the key is never printed, stored, or echoed in an error.
        pseudonym_key = key_file.expanduser().read_bytes() if key_file is not None else None
        store = TrustStore.open_readonly(trust_db_path(config.state_dir), client_id=config.client_id)
        try:
            if args.command == "export":
                from types import SimpleNamespace
                from .evidence import export_decision_records
                output = export_decision_records(SimpleNamespace(store=store, events=store.events),
                                                 pseudonym_key=pseudonym_key)
            elif args.command == "catalog":
                output = []
            elif args.command == "events":
                output = store.events(args.server)
            else:
                output = [record for record in store.records()
                          if args.server is None or record.server_id == args.server]
            print(json.dumps(_json(output), ensure_ascii=False, indent=2))
            return 0
        finally:
            store.close()
    async with TrustMonitor(config) as monitor:
        if args.command in {"status", "catalog", "events"}:
            output = getattr(monitor, args.command)(args.server)
        elif args.command == "observe":
            output = await monitor.observe(args.server)
        elif args.command == "review":
            output = await monitor.review_once(args.server)
        elif args.command in {"approve", "restore"}:
            output = await getattr(monitor, args.command)(
                args.server, revision=args.revision, expected_generation=args.generation,
                actor=args.actor)
        elif args.command == "quarantine":
            output = await monitor.quarantine(args.server, actor=args.actor, reason=args.reason)
        elif args.command == "call":
            arguments = json.loads(args.arguments)
            if not isinstance(arguments, dict):
                raise ValueError("--arguments must be a JSON object")
            selection = None
            if args.selection:
                from .managed_client import SelectionToken
                selection = SelectionToken(**json.loads(args.selection.read_text(encoding="utf-8")))
            method = monitor.observe_and_call if args.refresh else monitor.call_tool
            output = await method(args.server, args.tool, arguments, selection=selection)
        elif args.command in {"monitor", "serve"}:
            # main() runs these through _run_service, which also handles SIGTERM. Here
            # they run until cancelled, and the owner closes as for any other command.
            await _serve(monitor, args, config, asyncio.Event())
            return 0
        else:
            raise ValueError("unknown command")
        print(json.dumps(_json(output), ensure_ascii=False, indent=2))
        if args.command == "review" and {output.detector, output.assessment, output.outcome} & {"failed", "stale"}:
            return 1  # The assessment did not complete; nothing was approved (REQ-DEC-04).
        return 1 if getattr(output, "isError", False) else 0


# `monitor`/`serve` stopped, but not cleanly: the unclean marker is kept, so the next
# owner runs recovery (REQ-MON-03, REQ-ENF-07). Also used for any incomplete shutdown.
EXIT_UNCLEAN_STOP = 5


async def _serve(monitor: Any, args: argparse.Namespace, config: Any,
                 stop: asyncio.Event) -> None:
    """Monitoring, and the console for `serve`, inside the owner until `stop` is set."""
    console = None
    try:
        await monitor.start_monitor()
        if args.command == "serve":
            from .console import ConsoleServer
            console = await ConsoleServer(monitor, port=args.port).start()
            print(json.dumps({"console_url": console.url}), flush=True)
        else:
            print(json.dumps({"status": "monitoring", "client_id": config.client_id}), flush=True)
        await stop.wait()
    finally:
        if console is not None:
            await console.close()  # The port stops accepting before the owner closes.


_UNCLEAN_STOP_MESSAGES = {
    "incomplete": "cancelled work outlived shutdown_timeout; owned server processes were "
                  "reaped and ownership released; the unclean marker is kept, so the next "
                  "owner runs recovery",
    "owned": "an owned server transport could not be confirmed closed, so ownership was "
             "kept; the state-directory lock is released only because this process exits; "
             "the unclean marker is kept, so the next owner runs recovery",
    "faulted": "authoritative storage faulted; the unclean marker is kept, so the next "
               "owner runs recovery",
    "failed": "closing the owner failed; the unclean marker is kept, so the next owner "
              "runs recovery",
}


async def _stop_owner(monitor: Any, config: Any) -> int:
    """Close the owner after a requested stop and report the outcome (REQ-MON-03).

    Exit 0 only after a clean close: owned server processes reaped and the unclean
    marker removed. While an owned transport cannot be confirmed closed, ownership is
    kept and closing is retried for up to `shutdown_timeout`. Any other outcome prints
    one stable JSON object on stderr and returns EXIT_UNCLEAN_STOP.
    """
    import time
    from .sdk import ShutdownIncompleteError
    deadline = time.monotonic() + config.shutdown_timeout
    failure: BaseException | None = None
    while True:
        try:
            await monitor.aclose()
            failure = None
            break
        except ShutdownIncompleteError as exc:
            failure = exc
            remaining = deadline - time.monotonic()
            if exc.ownership_released or remaining <= 0:
                break
            await asyncio.sleep(min(0.25, remaining))  # Still the owner: retry the close.
        except Exception as exc:  # e.g. the unclean marker could not be removed
            failure = exc
            break
    marker_kept = monitor._owner.marker.exists()
    if failure is None and not marker_kept:
        return 0
    result: dict[str, Any]
    if isinstance(failure, ShutdownIncompleteError):
        kind = "incomplete" if failure.ownership_released else "owned"
        result = {"error": "ShutdownIncompleteError",
                  "ownership_released": failure.ownership_released}
    elif failure is None:
        # aclose() completes without error after a latched storage fault, keeping the marker.
        kind, result = "faulted", {"error": "StorageFaultError"}
    else:
        kind, result = "failed", {"error": type(failure).__name__}
    result["recovery_required"] = marker_kept
    result["message"] = _UNCLEAN_STOP_MESSAGES[kind]
    print(json.dumps(result), file=sys.stderr, flush=True)
    return EXIT_UNCLEAN_STOP


async def _run_service(args: argparse.Namespace) -> int:
    """`monitor` and `serve`: run until SIGTERM, then stop with bounded cleanup.

    SIGTERM is a routine stop, not a crash (REQ-MON-03): monitoring stops, the console
    stops accepting connections, owned server processes are reaped and ownership is
    released cleanly when appropriate (see _stop_owner). The handler is installed before
    the owner opens, so an early SIGTERM also stops cleanly. SIGINT keeps Python's
    handling: the owner closes as the exception unwinds, and the exit status is 130.
    """
    import signal
    from .sdk import TrustMonitor
    config = load_config(args.config)
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    try:
        loop.add_signal_handler(signal.SIGTERM, stop.set)
        handled = True
    except (NotImplementedError, RuntimeError, ValueError):
        handled = False  # e.g. Windows (unsupported): SIGTERM keeps its default action
    try:
        monitor = TrustMonitor(config)
        await monitor.__aenter__()
        try:
            await _serve(monitor, args, config, stop)
        except BaseException:
            await monitor.aclose()  # As `async with` would; errors reach main().
            raise
        return await _stop_owner(monitor, config)
    finally:
        if handled:
            loop.remove_signal_handler(signal.SIGTERM)


# After a command's outcome, remaining tasks get this long to honor cancellation.
_TEARDOWN_SECONDS = 2.0


def main(argv: list[str] | None = None) -> int:
    """Run one command and return its exit status.

    Like `asyncio.run`, except that teardown is bounded: a task that ignores
    cancellation (for example a server transport that cannot be confirmed closed)
    cannot keep the process alive after the outcome is known. In that case the
    streams are flushed and the process exits at once with the classified status; the
    store is already closed and an unclean marker, if any, is kept (REQ-MON-03).
    """
    args = parser().parse_args(argv)
    command = _run_service(args) if args.command in {"monitor", "serve"} else run(args)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    task = loop.create_task(command)
    restore_sigint = _cancel_on_first_sigint(loop, task)
    try:
        loop.run_until_complete(task)
    except KeyboardInterrupt:
        # A KeyboardInterrupt that still escaped: cancel the command so its owner closes
        # as it unwinds, as asyncio.run does.
        task.cancel()
        loop.run_until_complete(asyncio.wait({task}))
    except BaseException:
        pass  # The command's own outcome is classified below.
    finally:
        restore_sigint()
    code = _exit_status(task)
    if not _teardown(loop):
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)
    return code


def _cancel_on_first_sigint(loop: asyncio.AbstractEventLoop, task: asyncio.Task):
    """Like asyncio.run on Python 3.11+: the first SIGINT cancels the command (its owner
    then closes as it unwinds); a second one raises KeyboardInterrupt. Returns a function
    that restores the previous handler. Only installed over Python's default handler."""
    import signal
    import threading
    if (threading.current_thread() is not threading.main_thread()
            or signal.getsignal(signal.SIGINT) is not signal.default_int_handler):
        return lambda: None
    interrupts = 0

    def handler(signum, frame):
        nonlocal interrupts
        interrupts += 1
        if interrupts == 1 and not task.done():
            task.cancel()
            loop.call_soon_threadsafe(lambda: None)  # wake the loop to deliver it
            return
        raise KeyboardInterrupt()

    signal.signal(signal.SIGINT, handler)
    return lambda: signal.signal(signal.SIGINT, signal.default_int_handler)


def _teardown(loop: asyncio.AbstractEventLoop) -> bool:
    """Cancel what remains within a bound; False if a task still ignores cancellation."""
    pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
    for task in pending:
        task.cancel()
    if pending:
        loop.run_until_complete(asyncio.wait(pending, timeout=_TEARDOWN_SECONDS))
    if any(not task.done() for task in pending):
        return False
    for task in pending:
        if not task.cancelled():
            task.exception()  # retrieved
    loop.run_until_complete(loop.shutdown_asyncgens())
    try:
        loop.run_until_complete(asyncio.wait_for(loop.shutdown_default_executor(),
                                                 _TEARDOWN_SECONDS))
    except (asyncio.TimeoutError, RuntimeError):
        pass
    asyncio.set_event_loop(None)
    loop.close()
    return True


def _exit_status(task: asyncio.Task) -> int:
    if task.cancelled():
        return 130
    exc = task.exception()
    if exc is None:
        return task.result()
    if isinstance(exc, KeyboardInterrupt):
        return 130
    # Arbitrary transport/config/model errors may contain credentials or untrusted text.
    # Emit stable error types and only the library's explicitly classified block reason.
    from .managed_client import CallBlocked, DispatchedCallUnrecorded, ToolOutcomeUnknown
    from .sdk import ShutdownIncompleteError
    result: dict[str, Any] = {"error": type(exc).__name__}
    if isinstance(exc, ShutdownIncompleteError):
        # The owner did not close cleanly; the unclean marker is kept (REQ-MON-03).
        result["ownership_released"] = exc.ownership_released
        result["recovery_required"] = True
        result["message"] = _UNCLEAN_STOP_MESSAGES[
            "incomplete" if exc.ownership_released else "owned"]
        call = _call_outcome(exc)
        if call is not None:
            # Keep the call's own classification: a dispatched call must never look
            # retryable merely because the close afterwards was incomplete.
            result["call_error"] = type(call).__name__
            if isinstance(call, CallBlocked):
                result["reason"] = call.reason
            else:
                result["dispatched"] = True
                if isinstance(call, DispatchedCallUnrecorded):
                    print(json.dumps(_json(call.result), ensure_ascii=False, indent=2))
        print(json.dumps(result), file=sys.stderr)
        return EXIT_UNCLEAN_STOP
    if isinstance(exc, CallBlocked):
        result["reason"] = exc.reason
        print(json.dumps(result), file=sys.stderr)
        return 3  # Refused before dispatch.
    if isinstance(exc, (ToolOutcomeUnknown, DispatchedCallUnrecorded)):
        # The request was handed to the transport and may have taken effect (this is
        # not proof the server received it): never a refusal,
        # and never retried automatically (REQ-ENF-05/08).
        result["dispatched"] = True
        if isinstance(exc, DispatchedCallUnrecorded):
            print(json.dumps(_json(exc.result), ensure_ascii=False, indent=2))
        print(json.dumps(result), file=sys.stderr)
        return 4
    print(json.dumps(result), file=sys.stderr)
    return 1


def _call_outcome(exc: BaseException) -> BaseException | None:
    """The call outcome an incomplete close interrupted, if any (via exception context)."""
    from .managed_client import CallBlocked, DispatchedCallUnrecorded, ToolOutcomeUnknown
    seen = set()
    current = exc.__context__
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, (CallBlocked, ToolOutcomeUnknown, DispatchedCallUnrecorded)):
            return current
        current = current.__context__
    return None


if __name__ == "__main__":
    raise SystemExit(main())
