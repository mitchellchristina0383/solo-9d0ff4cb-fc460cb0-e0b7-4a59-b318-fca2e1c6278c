"""Pydantic models for the rule-management HTTP API."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

DEFAULT_PORT = 53


def normalize_suffix(suffix: str) -> str:
    """Normalize a DNS suffix to a lower-case, dot-terminated wire label form.

    The empty string (root) means "every name" and is used for the default
    upstream rule.
    """
    suffix = (suffix or "").strip().lower()
    if suffix in ("", ".", "@"):
        return ""
    if not suffix.endswith("."):
        suffix += "."
    # Reject obviously malformed labels early.
    for label in suffix.rstrip(".").split("."):
        if not label or len(label) > 63:
            raise ValueError(f"invalid DNS label in suffix: {suffix!r}")
    if len(suffix) > 255:
        raise ValueError("suffix too long")
    return suffix


def normalize_name(name: str) -> str:
    name = (name or "").strip().lower()
    if not name:
        raise ValueError("empty name")
    if not name.endswith("."):
        name += "."
    return name


def split_endpoint(endpoint: str) -> tuple[str, int]:
    """Split 'host' / 'host:port' / '[v6]:port' into (host, port)."""
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        end = endpoint.find("]")
        if end == -1:
            raise ValueError(f"invalid upstream endpoint: {endpoint!r}")
        host = endpoint[1:end]
        rest = endpoint[end + 1:]
        if rest == "":
            return host, DEFAULT_PORT
        if not rest.startswith(":"):
            raise ValueError(f"invalid upstream endpoint: {endpoint!r}")
        return host, int(rest[1:])
    if endpoint.count(":") == 1:
        host, port = endpoint.rsplit(":", 1)
        return host, int(port)
    if ":" in endpoint:
        # Bare IPv6 without brackets -> default port.
        return endpoint, DEFAULT_PORT
    return endpoint, DEFAULT_PORT


class Rule(BaseModel):
    """A single forwarding rule: names ending with ``suffix`` go to ``upstream``."""

    suffix: str = Field(..., description="DNS suffix, e.g. 'lab.example.com'. Use '' for the default rule.")
    upstream: str = Field(..., description="Upstream resolver endpoint 'host' or 'host:port'.")

    @field_validator("suffix")
    @classmethod
    def _check_suffix(cls, v: str) -> str:
        return normalize_suffix(v)

    @field_validator("upstream")
    @classmethod
    def _check_upstream(cls, v: str) -> str:
        host, port = split_endpoint(v)
        if not host:
            raise ValueError("upstream host must not be empty")
        if not 1 <= port <= 65535:
            raise ValueError("upstream port out of range")
        return v


class RuleSet(BaseModel):
    """Full rule set pushed via the API. Exactly one default rule is required."""

    default_upstream: str = Field(..., description="Upstream used when no suffix rule matches.")
    rules: list[Rule] = Field(default_factory=list)

    @field_validator("default_upstream")
    @classmethod
    def _check_default(cls, v: str) -> str:
        host, port = split_endpoint(v)
        if not host:
            raise ValueError("default upstream host must not be empty")
        if not 1 <= port <= 65535:
            raise ValueError("default upstream port out of range")
        return v

    @field_validator("rules")
    @classmethod
    def _check_unique(cls, v: list[Rule]) -> list[Rule]:
        seen: set[str] = set()
        for rule in v:
            if rule.suffix in seen:
                raise ValueError(f"duplicate suffix rule: {rule.suffix!r}")
            seen.add(rule.suffix)
        return v


class CacheEntryView(BaseModel):
    entry_id: int
    qname: str
    qtype: str
    upstream: str
    rcode: str
    ttl_remaining: float
    ttl_original: int
    expires_at: float
    refresh_scheduled: bool
    refresh_in_flight: bool


class StatsView(BaseModel):
    queries_total: int
    cache_hits: int
    upstream_queries: int
    redispatch_on_rule_change: int
    attempts_cancelled: int
    stale_replies_discarded: int
    servfail_responses: int
    upstream_timeouts: int = 0
    refreshes_triggered: int = 0
    refreshes_succeeded: int = 0
    refreshes_failed: int = 0
    refreshes_rejected: int = 0
    refreshes_cancelled: int = 0
    in_flight: int
    refreshes_in_flight: int
    cache_entries: int
    upstreams: dict[str, str]
