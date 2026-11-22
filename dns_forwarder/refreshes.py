"""Registry of background early-refresh jobs.

A refresh job is a single asyncio task that re-queries one (qname, qtype) at
the upstream selected by the current rules while clients keep being served
from the still-valid cache entry. Jobs are keyed by the cache entry id, which
guarantees:

* at most one outstanding refresh per cached answer (the entry's
  ``refresh_scheduled`` flag plus this registry);
* a flush or a rule-change eviction that invalidates the entry also cancels
  its job, and any reply that nevertheless arrives is rejected by the cache's
  entry-id guard (see :meth:`dns_forwarder.cache.DNSCache.apply_refresh`).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable


@dataclass
class RefreshJob:
    entry_id: int
    qname: str
    qtype: int
    upstream: str
    task: asyncio.Task = field(repr=False)


class RefreshRegistry:
    def __init__(self) -> None:
        self._jobs: dict[int, RefreshJob] = {}
        # Entry ids whose cancellation was already counted by the caller, so
        # the job's own CancelledError handler does not count it twice.
        self._silent: set[int] = set()

    def add(
        self,
        entry_id: int,
        qname: str,
        qtype: int,
        upstream: str,
        coro_factory: Callable[[], Awaitable[None]],
    ) -> RefreshJob | None:
        """Schedule a refresh for an entry; no-op if one is already running."""
        if entry_id in self._jobs:
            return None
        task = asyncio.ensure_future(coro_factory())
        job = RefreshJob(
            entry_id=entry_id,
            qname=qname.lower(),
            qtype=qtype,
            upstream=upstream,
            task=task,
        )
        self._jobs[entry_id] = job
        task.add_done_callback(lambda _t: self._discard(entry_id))
        return job

    def _discard(self, entry_id: int) -> None:
        self._jobs.pop(entry_id, None)
        self._silent.discard(entry_id)

    def is_silent(self, entry_id: int) -> bool:
        return entry_id in self._silent

    def cancel(self, entry_id: int) -> RefreshJob | None:
        """Cancel the refresh for one entry id. Returns the job if one existed."""
        job = self._jobs.pop(entry_id, None)
        if job is None:
            return None
        self._silent.add(entry_id)
        job.task.cancel()
        return job

    def cancel_all(self) -> list[RefreshJob]:
        """Cancel every outstanding refresh (used on cache flush/shutdown)."""
        jobs = list(self._jobs.values())
        self._jobs.clear()
        for job in jobs:
            self._silent.add(job.entry_id)
            job.task.cancel()
        return jobs

    def all(self) -> list[RefreshJob]:
        return list(self._jobs.values())

    def __len__(self) -> int:
        return len(self._jobs)
