"""Single owning process and durable unclean-exit recovery (REQ-LIB-04/05, ENF-07)."""
from __future__ import annotations
import fcntl
import json
import os
import uuid
from pathlib import Path
from .trust_store import TrustError, inspect_schema

class OwnershipError(TrustError):
    pass

class StateOwner:
    def __init__(self, directory: Path):
        self.directory = Path(directory).resolve()
        self.marker = self.directory / 'owner.unclean'
        self.lock = None
        self.faulted = False
        self.recovery_required = False

    def acquire(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = (self.directory / 'owner.lock').open('a+b')
        try:
            fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            self.lock = None
            raise OwnershipError('state directory already has an owner') from None
        try:
            inspect_schema(self.directory / 'trust.sqlite3')
            self.recovery_required = self.marker.exists()
            temporary = self.directory / ('owner.' + uuid.uuid4().hex + '.tmp')
            try:
                with temporary.open('x', encoding='utf8') as stream:
                    json.dump({'pid': os.getpid(), 'nonce': uuid.uuid4().hex}, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.marker)
                self._sync_directory()
            finally:
                temporary.unlink(missing_ok=True)
        except BaseException:
            self.release(clean=False)
            raise

    def _sync_directory(self):
        fd = os.open(self.directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def release(self, *, clean: bool):
        try:
            if clean and not self.faulted and self.lock is not None:
                self.marker.unlink(missing_ok=True)
                try:
                    self._sync_directory()
                except OSError:
                    # A failed durable removal must not appear as a clean next open.
                    self.faulted = True
                    with self.marker.open('w') as stream:
                        stream.write('{"unclean":true}')
                        stream.flush()
                        try:
                            os.fsync(stream.fileno())
                        except OSError:
                            pass
                    raise
        finally:
            if self.lock is not None:
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_UN)
                self.lock.close()
                self.lock = None
