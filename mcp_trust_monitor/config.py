"""Explicit configuration. Library imports never read credentials or launch processes."""
from __future__ import annotations
from dataclasses import dataclass
import inspect
import math
import os
import shutil
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping
from .managed_client import ServerConfig
from .trust_store import TrustError

class ConfigurationError(TrustError):
    pass

@dataclass(frozen=True)
class MonitorConfig:
    state_dir: Path
    policy_path: Path
    servers: Mapping[str, ServerConfig]
    client_id: str = 'default'
    poll_interval: float = 30.0
    timeout_seconds: float = 15.0
    shutdown_timeout: float = 10.0
    max_concurrency: int = 4
    detector: Any = None
    reviewer: Callable | None = None
    history_sink: Callable | None = None
    # Automatic assessments of one unchanged failed or stale context, with exponential
    # backoff from poll_interval; a changed context or reset_review_retries re-arms it.
    review_max_attempts: int = 3

    def __post_init__(self):
        if self.reviewer is not None and not (inspect.iscoroutinefunction(self.reviewer) or
                inspect.iscoroutinefunction(getattr(self.reviewer, "__call__", None))):
            raise ConfigurationError("reviewer must be an async callable (monitor, server_id)")
        if not isinstance(self.client_id, str) or not self.client_id or not isinstance(self.servers, Mapping) or not self.servers:
            raise ConfigurationError('client_id and explicitly configured servers are required')
        timings = (self.poll_interval, self.timeout_seconds, self.shutdown_timeout)
        if any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
               for value in timings):
            raise ConfigurationError('timeouts and poll interval must be finite positive numbers')
        if type(self.max_concurrency) is not int or self.max_concurrency < 1:
            raise ConfigurationError('max_concurrency must be a positive integer')
        if type(self.review_max_attempts) is not int or self.review_max_attempts < 1:
            raise ConfigurationError('review_max_attempts must be a positive integer')
        profiles = {}
        for sid, server in self.servers.items():
            if (not isinstance(sid, str) or not sid or not isinstance(server, ServerConfig)
                    or server.server_id != sid or not isinstance(server.command, str)
                    or not server.command or '\x00' in server.command):
                raise ConfigurationError('invalid server launch profile')
            if (not isinstance(server.args, (tuple, list))
                    or any(not isinstance(arg, str) or '\x00' in arg for arg in server.args)):
                raise ConfigurationError('server args must be literal strings')
            if server.cwd is not None and (not isinstance(server.cwd, str) or not server.cwd or '\x00' in server.cwd):
                raise ConfigurationError('invalid server working directory')
            for environment, references in ((server.env, False), (server.secret_env, True)):
                if environment is None and not references:
                    continue
                if (not isinstance(environment, Mapping)
                        or any(not isinstance(key, str) or not key or '=' in key or '\x00' in key
                               or not isinstance(value, str) or '\x00' in value
                               or (references and (not value or '=' in value))
                               for key, value in environment.items())):
                    raise ConfigurationError('invalid environment mapping or credential reference')
            if server.origin not in ('live', 'synthetic_fixture'):
                raise ConfigurationError('origin must be live or synthetic_fixture')
            if set(server.env or {}) & set(server.secret_env):
                raise ConfigurationError('environment setting cannot also be a secret reference')
            executable = shutil.which(server.command) or server.command
            executable = os.path.abspath(executable)
            cwd = str(Path(server.cwd or os.getcwd()).resolve())
            profiles[sid] = ServerConfig(sid, executable, tuple(server.args),
                MappingProxyType(dict(server.env or {})), cwd, server.origin,
                MappingProxyType(dict(server.secret_env)))
        object.__setattr__(self, 'servers', MappingProxyType(profiles))
        object.__setattr__(self, 'state_dir', Path(self.state_dir).resolve())
        object.__setattr__(self, 'policy_path', Path(self.policy_path).resolve())
