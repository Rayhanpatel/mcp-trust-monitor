"""Public, dependency-free records and adapter contract for reviewed memory."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol, Sequence


class MemoryError(Exception):
    """Memory failed; it supplies no decision or authorization authority."""


class MemoryConflict(MemoryError):
    """An operator action no longer matches the reviewed state."""


class MemoryIntegrityError(MemoryError):
    """A source, reference, body, version or capability could not be verified."""


class MemoryStale(MemoryError):
    """Context changed while external work was pending."""


class PublicationPending(MemoryError):
    """Publication remains inactive and can be inspected or reconciled."""


class Record:
    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Verdict(Record):
    verdict_id: str
    observation_id: str
    assessment_event_id: str
    server_id: str
    revision: str
    policy_binding: str
    value: str
    actor: str
    rationale: str
    active: bool
    supersedes: str | None
    created_at: str
    origin: str = "unrecorded"


@dataclass(frozen=True)
class Lesson(Record):
    lesson_id: str
    series_id: str
    version: int
    verdict_id: str
    policy_binding: str
    scope: str
    body: str
    digest: str
    state: str
    reviewer: str | None
    operation_id: str | None
    content_id: str | None
    node_id: str | None
    remote_version: str | None
    created_at: str
    updated_at: str
    last_error: str | None
    origin: str = "unrecorded"


@dataclass(frozen=True)
class UploadReceipt(Record):
    content_id: str
    node_id: str


@dataclass(frozen=True)
class NodeStatus(Record):
    node_id: str
    content_id: str
    status: str  # processing | completed | failed


@dataclass(frozen=True)
class RemoteContent(Record):
    node_id: str
    content_id: str
    version: str
    text: str


@dataclass(frozen=True)
class SearchPassage(Record):
    content_id: str
    text: str
    version: str | None = None
    source_version_id: str | None = None


class MemoryBackend(Protocol):
    """Normalize an evidenced private-KB API. Uploads MUST NOT be retried.

    Capability fields are configured by a trusted operator after a real probe;
    they are not learned from returned text. No implementation is bundled here.
    """

    capability_verified: bool
    capability_evidence: str

    async def upload_raw(self, text: str, title: str) -> UploadReceipt: ...
    async def node(self, node_id: str) -> NodeStatus: ...
    async def node_content(self, node_id: str, *, version: str | None = None) -> RemoteContent: ...
    async def search_context(self, query: str, *, content_ids: tuple[str, ...],
                             top_k: int) -> Sequence[SearchPassage]: ...


@dataclass(frozen=True)
class MemorySnapshot(Record):
    client_id: str
    scope: str
    policy_binding: str
    registry_revision: int | None
    lessons: tuple[Lesson, ...]
    enabled: bool


@dataclass(frozen=True)
class RetrievedPrecedent(Record):
    lesson_id: str
    version: int
    digest: str
    content_id: str
    remote_version: str
    text: str
    source_version_id: str | None = None


@dataclass(frozen=True)
class RetrievedMemory(Record):
    snapshot: MemorySnapshot
    passages: tuple[RetrievedPrecedent, ...]
    requested_content_ids: tuple[str, ...]
    status: str  # disabled | none_eligible | none_returned | returned

    @property
    def lesson_ids(self) -> tuple[str, ...]:
        return tuple(sorted({item.lesson_id for item in self.passages}))

    @property
    def returned_content_ids(self) -> tuple[str, ...]:
        return tuple(sorted({item.content_id for item in self.passages}))
