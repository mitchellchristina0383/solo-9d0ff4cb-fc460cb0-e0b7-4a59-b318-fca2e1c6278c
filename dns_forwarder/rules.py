"""In-memory forwarding-rule store with longest-suffix matching.

The store is mutated only through :meth:`RuleStore.replace` /
:meth:`RuleStore.upsert` / :meth:`RuleStore.delete`. Every mutation bumps a
monotonic version and returns a :class:`RuleDiff` describing the previous and
new mapping, which the cache and the in-flight query registry use to decide
what must be invalidated or redispatched.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .models import Rule, RuleSet, normalize_suffix, split_endpoint


def endpoint_key(host: str, port: int) -> str:
    """Canonical textual key for an upstream endpoint."""
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


@dataclass(frozen=True)
class Matcher:
    """Immutable snapshot of a rule set, safe to use after later mutations."""

    default_upstream: str
    suffix_upstreams: dict[str, str]  # normalized trailing-dot suffix -> key

    def match(self, qname: str) -> str:
        """Return the upstream key for ``qname`` using longest-suffix match."""
        qname = qname.lower()
        best_suffix: str | None = None
        for suffix in self.suffix_upstreams:
            if suffix == qname or qname.endswith("." + suffix):
                if best_suffix is None or len(suffix) > len(best_suffix):
                    best_suffix = suffix
        if best_suffix is None:
            return self.default_upstream
        return self.suffix_upstreams[best_suffix]


@dataclass
class RuleDiff:
    version: int
    old: Matcher
    new: Matcher

    def upstream_changed(self, qname: str) -> bool:
        return self.old.match(qname) != self.new.match(qname)


@dataclass
class RuleStore:
    default_upstream: str
    # normalized suffix -> endpoint key; "" is only kept as default_upstream
    _suffixes: dict[str, str] = field(default_factory=dict, init=False)
    _version: int = field(default=0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    @property
    def version(self) -> int:
        return self._version

    @property
    def lock(self) -> asyncio.Lock:
        return self._lock

    def matcher(self) -> Matcher:
        return Matcher(self.default_upstream, dict(self._suffixes))

    def to_ruleset(self) -> RuleSet:
        return RuleSet(
            default_upstream=self.default_upstream,
            rules=[Rule(suffix=s, upstream=u) for s, u in sorted(self._suffixes.items())],
        )

    def _build_matcher(self, default_upstream: str, rules: list[Rule]) -> Matcher:
        host, port = split_endpoint(default_upstream)
        default_key = endpoint_key(host, port)
        suffix_map: dict[str, str] = {}
        for rule in rules:
            rhost, rport = split_endpoint(rule.upstream)
            suffix_map[rule.suffix] = endpoint_key(rhost, rport)
        return Matcher(default_key, suffix_map)

    def replace(self, body: RuleSet) -> RuleDiff:
        """Atomically replace the whole rule set."""
        old = self.matcher()
        new = self._build_matcher(body.default_upstream, body.rules)
        self.default_upstream = new.default_upstream
        self._suffixes = new.suffix_upstreams
        self._version += 1
        return RuleDiff(self._version, old, new)

    def upsert(self, rule: Rule) -> RuleDiff:
        old = self.matcher()
        host, port = split_endpoint(rule.upstream)
        self._suffixes[rule.suffix] = endpoint_key(host, port)
        self._version += 1
        return RuleDiff(self._version, old, self.matcher())

    def delete(self, suffix: str) -> RuleDiff:
        normalized = normalize_suffix(suffix)
        if normalized == "":
            raise ValueError("the default rule cannot be deleted; replace it via PUT /rules")
        if normalized not in self._suffixes:
            raise KeyError(normalized)
        old = self.matcher()
        del self._suffixes[normalized]
        self._version += 1
        return RuleDiff(self._version, old, self.matcher())
