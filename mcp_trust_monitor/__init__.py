"""MCP Trust Monitor: revision-bound trust enforcement for a managed MCP client."""
"""Public API for a locally owned, approval-bound MCP client.

Importing this module performs no I/O and does not import optional cloud SDKs.
"""
from .config import ConfigurationError, MonitorConfig
from .evidence import (DecisionRecord, DecisionRecords, EvidenceSource,
                       ObservationEvidence, export_decision_records)
from .managed_client import (CallBlocked, CatalogEntry, DispatchedCallUnrecorded,
                             ObservationError, SelectionToken, ServerConfig,
                             ToolOutcomeUnknown)
from .ownership import OwnershipError
from .policy import DetectorBinding, PolicyRef, load_policy
from .sdk import (AssessmentContext, AssessmentNotReady, MonitorHealth, ReviewResult,
                  SessionHealth, ShutdownIncompleteError, TrustMonitor)
from .trust_store import (AssessmentOutcome, ObservationRequiredError,
                          SchemaCompatibilityError, StaleDecisionError, StorageFaultError,
                          TrustError, TrustRecord, TrustState)

__version__ = "0.2.0a1"
__all__ = ["TrustMonitor", "MonitorConfig", "ConfigurationError", "ServerConfig",
           "SelectionToken", "CatalogEntry", "PolicyRef", "DetectorBinding", "load_policy",
           "TrustState", "TrustRecord", "AssessmentOutcome", "TrustError",
           "CallBlocked", "ObservationError", "ToolOutcomeUnknown", "DispatchedCallUnrecorded",
           "OwnershipError", "ShutdownIncompleteError",
           "StorageFaultError", "SchemaCompatibilityError", "StaleDecisionError",
           "ObservationRequiredError", "ReviewResult", "AssessmentContext", "AssessmentNotReady",
           "MonitorHealth",
           "SessionHealth", "EvidenceSource", "DecisionRecord", "DecisionRecords",
           "ObservationEvidence", "export_decision_records"]
