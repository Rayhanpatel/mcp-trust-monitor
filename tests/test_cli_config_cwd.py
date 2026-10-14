"""JSON CLI launch paths (REQ-LIB-02, REQ-REV-04/05; findings R5 and R11).

An omitted or null ``cwd`` resolves to the config file's directory, like every other
relative path in that file, so the same config launches the same profile with the
same launch identity from any invoking directory. Explicit relative (config-relative)
and absolute values are unchanged, and the SDK keeps its own documented semantics.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from conftest import REPO_ROOT
from mcp_trust_monitor import MonitorConfig, ServerConfig
from mcp_trust_monitor.library_cli import load_config

SERVER = REPO_ROOT / "examples" / "external_stdio_server.py"
OMITTED = object()


def definition(directory: Path, description: str) -> None:
    (directory / "definition.json").write_text(json.dumps(
        {"name": "echo", "description": description, "inputSchema": {"type": "object"}}))


def layout(tmp_path: Path, cwd=OMITTED):
    """A config directory and two unrelated caller directories with different data."""
    root, callers = tmp_path / "project", (tmp_path / "caller-a", tmp_path / "caller-b")
    for directory in (root, *callers):
        directory.mkdir(parents=True)
    definition(root, "from the config directory")
    for directory in callers:
        definition(directory, "from " + directory.name)
    (root / "policy.json").write_text(json.dumps({"policy_id": "cwd", "revision": "1", "rules": []}))
    server = {"server_id": "local", "command": sys.executable, "origin": "synthetic_fixture",
              "args": [str(SERVER), "--definition", "definition.json", "--calls", "calls.jsonl"]}
    if cwd is not OMITTED:
        server["cwd"] = cwd
    config = root / "config.json"
    config.write_text(json.dumps({"state_dir": "state", "policy_path": "policy.json",
                                  "timeout_seconds": 30, "servers": [server]}))
    return config, root.resolve(), [directory.resolve() for directory in callers]


def cli(config: Path, *args: str, cwd: Path) -> subprocess.CompletedProcess:
    environment = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    return subprocess.run([sys.executable, "-m", "mcp_trust_monitor", "--config", str(config), *args],
                          capture_output=True, text=True, timeout=120, cwd=str(cwd), env=environment)


def configure_server(config: Path, **changes) -> None:
    document = json.loads(config.read_text())
    document["servers"][0].update(changes)
    config.write_text(json.dumps(document))


def executable(directory: Path, name: str = "server") -> Path:
    """A real executable that marks its own location before serving MCP stdio."""
    runner = directory / name
    runner.write_text(
        "#!" + sys.executable + "\n"
        "import os, sys\nfrom pathlib import Path\n"
        "Path(__file__).with_name('launched.txt').write_text('launched')\n"
        f"os.execv({sys.executable!r}, [{sys.executable!r}] + sys.argv[1:])\n"
    )
    runner.chmod(0o700)
    return runner


@pytest.mark.parametrize("cwd", [OMITTED, None], ids=["omitted", "null"])
def test_separate_processes_from_different_callers_launch_the_same_profile(tmp_path, cwd):
    config, root, callers = layout(tmp_path, cwd)
    observed = []
    for caller in callers:
        result = cli(config, "observe", "local", cwd=caller)
        assert result.returncode == 0, result.stderr[-500:]
        observed.append(json.loads(result.stdout))
    assert observed[0]["launch_identity"] == observed[1]["launch_identity"]
    assert [item["observed_tools"][0]["description"] for item in observed] == [
        "from the config directory"] * 2
    assert observed[0]["observed_revision"] == observed[1]["observed_revision"]
    # The server's own relative output went beside the config, not into either caller.
    assert (root / "calls.jsonl").exists()
    assert not any((caller / "calls.jsonl").exists() for caller in callers)
    events = cli(config, "events", cwd=callers[1])
    assert events.returncode == 0, events.stderr[-500:]
    kinds = [item["event_type"] for item in json.loads(events.stdout)]
    assert kinds.count("observed_new") == 1
    assert not {"launch_identity_changed", "revision_changed", "approval_invalidated"} & set(kinds)


@pytest.mark.parametrize("cwd", [OMITTED, None, "."], ids=["omitted", "null", "dot"])
def test_omitted_null_and_dot_cwd_all_mean_the_config_directory(tmp_path, monkeypatch, cwd):
    config, root, callers = layout(tmp_path, cwd)
    identities = set()
    for caller in callers:
        monkeypatch.chdir(caller)
        server = load_config(config).servers["local"]
        assert server.cwd == str(root)
        identities.add(server.launch_identity)
    monkeypatch.chdir(root)
    identities.add(load_config(config).servers["local"].launch_identity)
    assert len(identities) == 1


def test_explicit_relative_and_absolute_cwd_are_unchanged(tmp_path, monkeypatch):
    config, root, callers = layout(tmp_path, "data")
    elsewhere = (tmp_path / "elsewhere").resolve()
    for caller in callers:
        monkeypatch.chdir(caller)
        assert load_config(config).servers["local"].cwd == str(root / "data")
    absolute, _, _ = layout(tmp_path / "absolute", str(elsewhere))
    for caller in callers:
        monkeypatch.chdir(caller)
        assert load_config(absolute).servers["local"].cwd == str(elsewhere)


@pytest.mark.parametrize("cwd", ["", 5, ["data"], {"path": "data"}])
def test_invalid_cwd_is_rejected_before_any_state_or_launch(tmp_path, cwd):
    config, root, callers = layout(tmp_path, cwd)
    result = cli(config, "observe", "local", cwd=callers[0])
    assert result.returncode == 1
    assert json.loads(result.stderr.strip().splitlines()[-1])["error"] in {"ValueError", "TypeError"}
    assert not (root / "state").exists()
    assert not any((directory / "calls.jsonl").exists() for directory in (root, *callers))


def test_sdk_server_config_without_cwd_still_uses_the_process_directory(tmp_path, monkeypatch):
    """The SDK contract is separate: ServerConfig(cwd=None) is the process working
    directory when the MonitorConfig is constructed."""
    caller = tmp_path / "caller"
    caller.mkdir()
    monkeypatch.chdir(caller)
    config = MonitorConfig(state_dir=tmp_path / "state", policy_path=tmp_path / "policy.json",
                           servers={"local": ServerConfig("local", sys.executable)})
    assert config.servers["local"].cwd == str(caller.resolve())


@pytest.mark.parametrize("command,cwd", [
    ("./server", OMITTED), ("./server", "data"), ("bin/../server", OMITTED),
], ids=["dot-slash", "separate-cwd", "nested-path"])
def test_relative_executable_launches_config_local_binary_from_both_callers(tmp_path, command, cwd):
    """Observation executes only the config-local runner, under one launch identity."""
    config, root, callers = layout(tmp_path, cwd)
    launch_cwd = root if cwd is OMITTED else root / cwd
    if launch_cwd != root:
        launch_cwd.mkdir()
        definition(launch_cwd, "from the explicit working directory")
    directories = list(dict.fromkeys([root, *callers, launch_cwd]))
    for directory in directories:
        executable(directory)
        (directory / "bin").mkdir()
    configure_server(config, command=command)
    observed = []
    for caller in callers:
        result = cli(config, "observe", "local", cwd=caller)
        assert result.returncode == 0, result.stderr[-500:]
        observed.append(json.loads(result.stdout))
    assert (root / "launched.txt").exists()
    assert not any((directory / "launched.txt").exists()
                   for directory in directories if directory != root)
    assert observed[0]["launch_identity"] == observed[1]["launch_identity"]
    assert observed[0]["observed_revision"] == observed[1]["observed_revision"]
    expected = "from the config directory" if cwd is OMITTED else "from the explicit working directory"
    assert [item["observed_tools"][0]["description"] for item in observed] == [expected] * 2
    assert (launch_cwd / "calls.jsonl").exists()
    assert not any((caller / "calls.jsonl").exists() for caller in callers)
    events = cli(config, "events", cwd=callers[1])
    assert events.returncode == 0, events.stderr[-500:]
    kinds = [item["event_type"] for item in json.loads(events.stdout)]
    assert kinds.count("observed_new") == 1
    assert not {"launch_identity_changed", "revision_changed", "approval_invalidated"} & set(kinds)


@pytest.mark.parametrize("command", ["./server", "bin/../server", "server/", ".", ".."])
def test_path_like_commands_resolve_beside_config_without_changing_process_cwd(tmp_path, monkeypatch, command):
    config, root, callers = layout(tmp_path, "data")
    configure_server(config, command=command)
    identities = set()
    for caller in callers:
        nested_caller = caller / "nested"
        nested_caller.mkdir()
        monkeypatch.chdir(nested_caller)
        server = load_config(config).servers["local"]
        assert server.command == str((root / command).resolve())
        assert server.cwd == str(root / "data")
        assert Path.cwd() == nested_caller
        identities.add(server.launch_identity)
    assert len(identities) == 1


def test_tilde_executable_expands_home_without_reinterpreting_args_or_secret_references(tmp_path, monkeypatch):
    config, root, callers = layout(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    command = executable(home)
    monkeypatch.setenv("HOME", str(home))
    reference = "CLI_CONFIG_TEST_UNRESOLVED_SECRET"
    monkeypatch.delenv(reference, raising=False)
    arguments = ["./data.json", "~/data.json", "$HOME/data.json", "*", "a b", "--flag=x/y"]
    configure_server(config, command="~/server", args=arguments, secret_env={"TOKEN": reference})
    for caller in callers:
        monkeypatch.chdir(caller)
        server = load_config(config).servers["local"]
        assert server.command == str(command)
        assert server.args == tuple(arguments)
        assert dict(server.secret_env) == {"TOKEN": reference}
        assert Path.cwd() == caller
    assert not (root / "state").exists()
    assert not (home / "launched.txt").exists()


def test_absolute_executable_preserves_symlink_path(tmp_path, monkeypatch):
    config, root, callers = layout(tmp_path)
    command = root / "python-link"
    command.symlink_to(sys.executable)
    configure_server(config, command=str(command))
    for caller in callers:
        monkeypatch.chdir(caller)
        assert load_config(config).servers["local"].command == str(command)


@pytest.mark.parametrize("command", [".venv/bin/python", "~/.venv/bin/python"], ids=["relative", "home"])
def test_executable_symlink_retains_virtualenv_prefix_and_packages(tmp_path, monkeypatch, command):
    """REQ-LIB-02: config-relative normalization must not dereference a venv Python."""
    config, root, callers = layout(tmp_path)
    virtualenv = root / ".venv"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(virtualenv)
    interpreter = virtualenv / "bin" / "python"
    assert interpreter.is_symlink()
    package_path = subprocess.run(
        [str(interpreter), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip()
    (Path(package_path) / "r11_venv_only.py").write_text("VALUE = 'config-local venv package'\n")
    monkeypatch.setenv("HOME", str(root))
    arguments = ["-I", "-c",
                 "import json, sys, r11_venv_only; "
                 "print(json.dumps({'prefix': sys.prefix, 'package': r11_venv_only.VALUE}))"]
    configure_server(config, command=command, args=arguments)
    identities = set()
    for caller in callers:
        monkeypatch.chdir(caller)
        server = load_config(config).servers["local"]
        result = subprocess.run([server.command, *server.args], cwd=server.cwd,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {
            "prefix": str(virtualenv), "package": "config-local venv package"}
        assert server.command == str(interpreter)
        identities.add(server.launch_identity)
    assert len(identities) == 1


def test_bare_command_uses_callers_path_search(tmp_path, monkeypatch):
    """Bare names retain PATH semantics, including deliberate caller dependence."""
    config, root, callers = layout(tmp_path)
    executable(root)
    for caller in callers:
        executable(caller)
    configure_server(config, command="server")
    identities = set()
    for caller in callers:
        monkeypatch.chdir(caller)
        monkeypatch.setenv("PATH", str(caller))
        server = load_config(config).servers["local"]
        assert server.command == str(caller / "server")
        identities.add(server.launch_identity)
        result = cli(config, "observe", "local", cwd=caller)
        assert result.returncode == 0, result.stderr[-500:]
        assert (caller / "launched.txt").exists()
    assert len(identities) == 2
    assert not (root / "launched.txt").exists()


@pytest.mark.parametrize("command", [None, "", 5, ["./server"], {"path": "./server"}, "./bad\x00command"])
def test_invalid_executable_is_rejected_before_any_state_or_launch(tmp_path, command):
    config, root, callers = layout(tmp_path)
    executable(root)
    configure_server(config, command=command)
    result = cli(config, "observe", "local", cwd=callers[0])
    assert result.returncode == 1
    assert json.loads(result.stderr.strip().splitlines()[-1])["error"] == "ConfigurationError"
    assert not (root / "state").exists()
    assert not (root / "launched.txt").exists()
