"""Registry of queries currently waiting on an upstream.

Each client query is represented by one :class:`InflightQuery` whose whole
lifecycle is a single asyncio task running the forwarder's attempt loop. The
*current* upstream attempt runs inside a child task so that a rule change can
cancel just that attempt (closing its UDP socket) while the parent loop
re-dispatches the query to the new upstream.
"""
from __future__ import annotations

import asyncio
import itertools
import time
from dataclasses import dataclass, field


@dataclass
class InflightQuery:
    id: int
    qname: str
    qtype: int
    packet: bytes                 # original wire query, reused for every attempt
    client_addr: tuple[str, int]
    created_at: float
    rule_version: int = 0
    upstream: str = ""
    attempts: int = 0
    attempt_task: asyncio.Task | None = field(default=None, repr=False)
    loop_task: asyncio.Task | None = field(default=None, repr=False)


class InflightRegistry:
    def __init__(self) -> None:
        self._queries: dict[int, InflightQuery] = {}
        self._counter = itertools.count(1)

    def add(
        self,
        qname: str,
        qtype: int,
        packet: bytes,
        client_addr: tuple[str, int],
        rule_version: int,
        upstream: str,
    ) -> InflightQuery:
        query = InflightQuery(
            id=next(self._counter),
            qname=qname.lower(),
            qtype=qtype,
            packet=packet,
            client_addr=client_addr,
            created_at=time.monotonic(),
            rule_version=rule_version,
            upstream=upstream,
        )
        self._queries[query.id] = query
        return query

    def remove(self, query_id: int) -> None:
        self._queries.pop(query_id, None)

    def all(self) -> list[InflightQuery]:
        return list(self._queries.values())

    def for_qname(self, qname: str) -> list[InflightQuery]:
        qname = qname.lower()
        return [q for q in self._queries.values() if q.qname == qname]

    def __len__(self) -> int:
        return len(self._queries)
