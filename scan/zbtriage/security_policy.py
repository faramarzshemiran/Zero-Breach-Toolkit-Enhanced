"""Central fail-closed security boundary for operations outside offline scanning.

OS sandboxing is not silently approximated by a Python socket monkeypatch.
High-assurance mode refuses operation until an external launcher proves the
platform-specific enforcement; this version makes no such assertion.
"""
from dataclasses import dataclass
from typing import Literal


class SecurityPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class RunPolicy:
    mode: Literal["offline", "update", "acquire"] = "offline"
    network: Literal["deny", "update-only", "collector-disclosed"] = "deny"
    external_execution: bool = False
    os_isolation_verified: bool = False

    def validate(self):
        if self.mode == "offline" and (self.network != "deny" or self.external_execution):
            raise SecurityPolicyError("offline mode may not request networking or external collectors")
        if self.mode == "acquire" and not self.external_execution:
            raise SecurityPolicyError("acquisition requires explicit external collector authorisation")
        if self.mode == "update" and self.network != "update-only":
            raise SecurityPolicyError("indicator updates require the dedicated update network policy")


def validate_requested_operation(args):
    if getattr(args, "high_assurance", False):
        raise SecurityPolicyError("OS-enforced isolation has not been independently established on this host; high-assurance mode refuses to run")
    if getattr(args, "collect_android", None) and not getattr(args, "allow_external_collector", False):
        raise SecurityPolicyError("external AndroidQF execution is disabled by default; review the collector independently before using --allow-external-collector")
    if getattr(args, "collect_android", None):
        raise SecurityPolicyError("third-party Android collector is quarantined in this hardened release; collect with independently reviewed acquisition tooling and use --phone on the local export")
    elif getattr(args, "update", False):
        policy = RunPolicy("update", "update-only")
    else:
        policy = RunPolicy()
    policy.validate()
    return policy
