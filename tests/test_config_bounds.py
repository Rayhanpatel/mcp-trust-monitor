"""Invalid configuration must fail before freshness math or process creation."""
from dataclasses import replace
import math
import sys

import pytest

from mcp_trust_monitor import ConfigurationError, MonitorConfig, ServerConfig


@pytest.fixture
def config(tmp_path):
    return MonitorConfig(tmp_path / "state", tmp_path / "policy.json",
                         {"external": ServerConfig("external", sys.executable)})


@pytest.mark.parametrize("field", ["poll_interval", "timeout_seconds", "shutdown_timeout"])
@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, True, "30", 0, -1])
def test_invalid_timeout_cannot_disable_freshness(config, field, value):
    with pytest.raises(ConfigurationError):
        replace(config, **{field: value})
    assert not config.state_dir.exists()


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "2"])
def test_concurrency_requires_positive_integer(config, value):
    with pytest.raises(ConfigurationError):
        replace(config, max_concurrency=value)


@pytest.mark.parametrize("options", [
    {"args": "--unexpected-character-iteration"}, {"args": (3,)},
    {"args": ("null\x00arg",)}, {"env": {"BAD=KEY": "value"}},
    {"env": {"KEY": 3}}, {"secret_env": {"TOKEN": ""}},
    {"secret_env": {"TOKEN": "BAD=REFERENCE"}}, {"cwd": ""},
])
def test_invalid_launch_profile_refused_without_io(config, options):
    server = replace(config.servers["external"], **options)
    with pytest.raises(ConfigurationError):
        replace(config, servers={"external": server})
    assert not config.state_dir.exists()
