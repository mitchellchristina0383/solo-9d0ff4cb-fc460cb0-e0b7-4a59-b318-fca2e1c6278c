"""Core DNS forwarding service.

Single event loop hosts three things:

* a UDP datagram endpoint that receives client queries;
* one attempt task per in-flight query, talking to the upstream selected by
  the current rule set;
* the FastAPI app (see :mod:`dns_forwarder.api`) that mutates the rule set.

Rule changes are applied synchronously by the API call and immediately:

1. cache entries whose name now points at a *different* upstream are evicted
   (entries whose upstream did not change keep their original expiry);
2. every in-flight query whose name changed upstream has its current attempt
   cancelled (the socket is closed, so a late reply from the old upstream can
   never reach the client) and a fresh attempt is sent to the new upstream.
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import suppress
from dataclasses import dataclass

from dnslib import DNSRecord, EDNS0, QTYPE, RCODE

from .cache import DNSCache, CacheEntry
from .inflight import InflightQuery, InflightRegistry
from .refreshes import RefreshRegistry
from .rules import RuleDiff, RuleStore

log = logging.getLogger("dns_forwarder")


@dataclass
class Stats:
    queries_total: int = 0
    cache_hits: int = 0
    upstream_queries: int = 0
    redispatch_on_rule_change: int = 0
    attempts_cancelled: int = 0
    stale_replies_discarded: int = 0
    servfail_responses: int = 0
    upstream_timeouts: int = 0
    # Background early refresh (RFC 8767-style) counters.
    refreshes_triggered: int = 0
    refreshes_succeeded: int = 0
    refreshes_failed: int = 0
    refreshes_rejected: int = 0   # late/uncachable results not written back
    refreshes_cancelled: int = 0  # cancelled by flush, rule change or shutdown


class _OneShotUDP(asyncio.DatagramProtocol):
    """UDP protocol that resolves a future with the first received datagram."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self.reply: asyncio.Future[bytes] = loop.create_future()
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.reply.done():
            self.reply.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.reply.done():
            self.reply.set_exception(exc)


class DNSForwarder:
    def __init__(
        self,
        rules: RuleStore,
        *,
        upstream_timeout: float = 2.0,
        refresh_ttl_ratio: float = 0.2,
    ) -> None:
        self.rules = rules
        self.cache = DNSCache()
        self.inflight = InflightRegistry()
        self.refreshes = RefreshRegistry()
        self.upstream_timeout = upstream_timeout
        # A positive cache hit whose remaining TTL is at or below this fraction
        # of the entry's original TTL schedules one background refresh.
        self.refresh_ttl_ratio = refresh_ttl_ratio
        self.stats = Stats()
        self._transport: asyncio.DatagramTransport | None = None

    # ------------------------------------------------------------------ UDP
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        log.info("UDP listener ready on %s", transport.get_extra_info("sockname"))

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.ensure_future(self.handle_query(data, addr))

    def error_received(self, exc: Exception) -> None:
        log.warning("UDP listener error: %r", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None:
            log.warning("UDP listener connection lost: %r", exc)

    def _send(self, packet: bytes, addr: tuple[str, int]) -> None:
        if self._transport is not None:
            self._transport.sendto(packet, addr)

    # ------------------------------------------------------------- handling
    async def handle_query(self, data: bytes, addr: tuple[str, int]) -> None:
        self.stats.queries_total += 1
        try:
            request = DNSRecord.parse(data)
        except Exception:
            log.info("unparseable datagram from %s (%d bytes)", addr, len(data))
            return
        if not request.questions:
            self._send_error(request, RCODE.FORMERR, addr)
            return

        question = request.questions[0]
        qname = str(question.qname).lower()
        qtype = getattr(question.qtype, "qtype", question.qtype)

        if qtype != QTYPE.A:
            # The service contract is A queries only; answer explicitly.
            self._send_error(request, RCODE.REFUSED, addr)
            return

        matcher = self.rules.matcher()
        cached = self.cache.get(qname, qtype)
        if cached is not None:
            self.stats.cache_hits += 1
            self._send_cached(cached, request.header.id, addr)
            log.debug("cache hit %s A (%s)", qname, cached.upstream)
            # Early refresh applies to positive A answers only: negative
            # answers have their own (short) negative TTL and are never
            # refreshed in the background.
            if not cached.negative:
                self._maybe_schedule_refresh(cached, matcher)
            return

        query = self.inflight.add(
            qname=qname,
            qtype=qtype,
            packet=request.pack(),
            client_addr=addr,
            rule_version=self.rules.version,
            upstream=matcher.match(qname),
        )
        query.loop_task = asyncio.ensure_future(self._attempt_loop(query, request))

    # ------------------------------------------------------ per-query loop
    async def _attempt_loop(self, query: InflightQuery, request: DNSRecord) -> None:
        try:
            while True:
                matcher = self.rules.matcher()
                upstream = matcher.match(query.qname)
                query.upstream = upstream
                query.rule_version = self.rules.version
                query.attempts += 1
                self.stats.upstream_queries += 1
                log.debug("query#%d %s -> attempt %d via %s",
                          query.id, query.qname, query.attempts, upstream)

                query.attempt_task = asyncio.ensure_future(
                    self._single_attempt(query, upstream)
                )
                try:
                    reply = await query.attempt_task
                except asyncio.CancelledError:
                    # The whole query task is being shut down -> stop.
                    if asyncio.current_task().cancelling() > 0:
                        raise
                    # Otherwise a rule change cancelled just this attempt.
                    # Re-evaluate and immediately re-dispatch to the new
                    # upstream.
                    log.debug("query#%d attempt cancelled by rule change", query.id)
                    continue

                if reply is None:
                    # Timeout or socket failure -> SERVFAIL, stop retrying.
                    self.stats.servfail_responses += 1
                    self._send_error(request, RCODE.SERVFAIL, query.client_addr)
                    return

                # Defence in depth: even if the reply arrived just before the
                # cancel landed, make sure the upstream that answered is still
                # the one the current rules select. Otherwise drop it and
                # re-dispatch; this is the "late reply from the old upstream"
                # path.
                current = self.rules.matcher()
                if current.match(query.qname) != upstream:
                    self.stats.stale_replies_discarded += 1
                    log.debug("query#%d stale reply from %s discarded",
                              query.id, upstream)
                    continue

                self._finalize_reply(query, request, reply, upstream)
                return
        finally:
            self.inflight.remove(query.id)

    async def _single_attempt(self, query: InflightQuery, upstream: str) -> DNSRecord | None:
        """One foreground attempt; failures count towards client SERVFAILs."""
        return await self._upstream_exchange(
            query.qname, query.packet, upstream, query_id=query.id
        )

    async def _upstream_exchange(
        self,
        qname: str,
        packet: bytes,
        upstream: str,
        *,
        query_id: int | None = None,
    ) -> DNSRecord | None:
        """Send one UDP query on a one-shot socket and parse one reply.

        Returns ``None`` on timeout, socket/ICMP error, unparseable datagram
        or question mismatch. Foreground and background (refresh) callers
        share this path so both get the same "one socket per attempt, close
        on cancel" guarantees.
        """
        host, _, port_s = upstream.rpartition(":")
        port = int(port_s)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        loop = asyncio.get_running_loop()
        protocol = _OneShotUDP(loop)

        # Retrieve any post-close exception (e.g. ICMP port unreachable) so the
        # garbage collector does not log an unretrieved future exception. A
        # cancelled future (refresh/attempt cancelled by a flush or rule
        # change) raises from .exception(), so it must be checked first.
        def _consume_exception(future: asyncio.Future) -> None:
            if not future.cancelled():
                future.exception()

        protocol.reply.add_done_callback(_consume_exception)
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol,
                remote_addr=(host, port),
            )
        except OSError as exc:
            log.warning("query#%s socket error for %s: %r", query_id, upstream, exc)
            return None
        try:
            transport.sendto(packet)
            # One socket per attempt: when the attempt is cancelled the
            # socket closes and any late datagram is dropped by the kernel.
            try:
                data = await asyncio.wait_for(protocol.reply, timeout=self.upstream_timeout)
            except asyncio.TimeoutError:
                self.stats.upstream_timeouts += 1
                log.warning("query#%s timeout waiting on %s", query_id, upstream)
                return None
            except Exception as exc:  # OSError, ICMP errors, ...
                log.warning("query#%s upstream I/O error %s: %r", query_id, upstream, exc)
                return None

            try:
                reply = DNSRecord.parse(data)
            except Exception:
                log.warning("query#%s unparseable reply from %s", query_id, upstream)
                return None
            if not reply.questions or str(reply.questions[0].qname).lower() != qname:
                log.warning("query#%s reply question mismatch from %s", query_id, upstream)
                return None
            return reply
        finally:
            transport.close()

    # -------------------------------------------------------- early refresh
    def _maybe_schedule_refresh(self, entry: CacheEntry, matcher) -> None:
        """Schedule one background refresh once the entry enters the TTL window."""
        if entry.refresh_scheduled:
            return  # each cached answer triggers at most one refresh
        remaining = entry.expires_at - time.monotonic()
        if remaining > entry.ttl * self.refresh_ttl_ratio:
            return
        upstream = matcher.match(entry.qname)
        entry.refresh_scheduled = True
        packet = DNSRecord.question(entry.qname, qtype=QTYPE[entry.qtype]).pack()
        job = self.refreshes.add(
            entry.entry_id,
            entry.qname,
            entry.qtype,
            upstream,
            lambda: self._refresh_job(
                entry_id=entry.entry_id,
                qname=entry.qname,
                qtype=entry.qtype,
                packet=packet,
                upstream=upstream,
            ),
        )
        if job is None:
            # A job for this entry id already exists; the flag stays set.
            return
        self.stats.refreshes_triggered += 1
        log.info(
            "early refresh scheduled for %s A (entry#%d, %.2fs of %ds TTL left) via %s",
            entry.qname, entry.entry_id, remaining, entry.ttl, upstream,
        )

    async def _refresh_job(
        self,
        *,
        entry_id: int,
        qname: str,
        qtype: int,
        packet: bytes,
        upstream: str,
    ) -> None:
        """Background refresh: never touches a client, never raises."""
        label = f"entry#{entry_id} {qname} A"
        try:
            # Defence in depth against a rule change that evicted the entry
            # before this coroutine started running: the cache guard below is
            # authoritative, this just avoids a pointless datagram.
            current = self.cache.get_entry(qname, qtype)
            if current is None or current.entry_id != entry_id:
                self.stats.refreshes_rejected += 1
                log.info("refresh %s skipped: entry already gone", label)
                return
            selected = self.rules.matcher().match(qname)
            if selected != upstream:
                # The name moved to another upstream; this job should have
                # been cancelled. Do not query the old upstream.
                self.stats.refreshes_rejected += 1
                log.info("refresh %s skipped: upstream now %s", label, selected)
                return

            reply = await self._upstream_exchange(qname, packet, upstream)
            if reply is None:
                # Refresh failed: keep the original entry and its expiry. Once
                # it expires, ordinary queries go back to the upstream as usual.
                self.stats.refreshes_failed += 1
                log.info("refresh %s failed, keeping original expiry", label)
                return

            # Re-check the rules: a reply from an upstream that is no longer
            # selected must never be cached.
            if self.rules.matcher().match(qname) != upstream:
                self.stats.refreshes_rejected += 1
                self.stats.stale_replies_discarded += 1
                log.info("refresh %s reply from stale upstream %s discarded",
                         label, upstream)
                return

            replaced = self.cache.apply_refresh(
                reply,
                upstream,
                qname=qname,
                qtype=qtype,
                entry_id=entry_id,
            )
            if replaced is None:
                # Flushed, evicted, replaced meanwhile, or reply not cacheable:
                # the late result must not be written back.
                self.stats.refreshes_rejected += 1
                log.info("refresh %s result rejected by cache guard", label)
                return

            self.stats.refreshes_succeeded += 1
            log.info(
                "refresh %s replaced with fresh entry#%d (ttl=%ds) from %s",
                label, replaced.entry_id, replaced.ttl, upstream,
            )
        except asyncio.CancelledError:
            if not self.refreshes.is_silent(entry_id):
                self.stats.refreshes_cancelled += 1
            log.info("refresh %s cancelled (flush, rule change or shutdown)", label)
            raise
        except Exception:
            # A background task must never die with an unhandled exception.
            self.stats.refreshes_failed += 1
            log.exception("refresh %s raised, keeping original expiry", label)

    def _finalize_reply(
        self,
        query: InflightQuery,
        request: DNSRecord,
        reply: DNSRecord,
        upstream: str,
    ) -> None:
        entry = self.cache.store(reply, upstream)
        if entry is not None:
            self._send_cached(entry, request.header.id, query.client_addr)
        else:
            reply.header.id = request.header.id
            self._send(reply.pack(), query.client_addr)

    # ------------------------------------------------------------ responses
    def _send_cached(self, entry, query_id: int, addr: tuple[str, int]) -> None:
        record = DNSRecord.parse(entry.raw)
        elapsed = time.monotonic() - entry.stored_at
        for section in (record.rr, record.auth, record.ar):
            for rr in section:
                # EDNS OPT records carry extended rcode/version in the TTL
                # field and must not be rewritten.
                if isinstance(rr.rdata, EDNS0):
                    continue
                rr.ttl = max(0, int(rr.ttl - elapsed))
        record.header.id = query_id
        self._send(record.pack(), addr)

    def _send_error(self, request: DNSRecord, rcode: int, addr: tuple[str, int]) -> None:
        reply = request.reply()
        reply.header.rcode = rcode
        self._send(reply.pack(), addr)

    # --------------------------------------------------------- rule changes
    def apply_diff(self, diff: RuleDiff) -> dict:
        """Apply a rule diff: evict moved cache entries, redispatch inflight.

        Runs entirely inside the rule store lock, so the HTTP call returns
        only once the new rules are live. It never waits on upstream answers.
        """
        before = self.cache.snapshot_entries()
        moved_ids = [
            entry.entry_id
            for entry in before.values()
            if entry.upstream != diff.new.match(entry.qname)
        ]
        evicted = self.cache.invalidate_moved(
            {key: entry.upstream for key, entry in before.items()},
            diff.new.match,
        )
        # Entries whose upstream changed are gone: their background refreshes
        # target the old upstream and must be cancelled. A late reply could
        # never pass the cache's entry-id guard anyway, but cancelling also
        # closes the one-shot socket so no useless datagram is waited on.
        refreshes_cancelled = 0
        for entry_id in moved_ids:
            if self.refreshes.cancel(entry_id) is not None:
                refreshes_cancelled += 1
                self.stats.refreshes_cancelled += 1

        redispatched = 0
        for query in self.inflight.all():
            new_upstream = diff.new.match(query.qname)
            if new_upstream != query.upstream:
                query.upstream = new_upstream
                query.rule_version = diff.version
                if query.attempt_task is not None and not query.attempt_task.done():
                    query.attempt_task.cancel()
                    self.stats.attempts_cancelled += 1
                redispatched += 1
                self.stats.redispatch_on_rule_change += 1
        log.info(
            "rule v%d applied: %d cache entries evicted, %d in-flight redispatched, "
            "%d refreshes cancelled",
            diff.version, evicted, redispatched, refreshes_cancelled,
        )
        return {"version": diff.version, "cache_evicted": evicted,
                "inflight_redispatched": redispatched,
                "refreshes_cancelled": refreshes_cancelled}

    def flush_cache(self) -> int:
        """Drop every cache entry and cancel its outstanding refresh."""
        jobs = self.refreshes.cancel_all()
        count = len(jobs)
        if count:
            self.stats.refreshes_cancelled += count
        flushed = self.cache.flush()
        log.info("cache flushed: %d entries removed, %d refreshes cancelled",
                 flushed, count)
        return flushed

    async def shutdown(self) -> None:
        jobs = self.refreshes.cancel_all()
        for query in self.inflight.all():
            if query.loop_task is not None:
                query.loop_task.cancel()
            if query.attempt_task is not None:
                query.attempt_task.cancel()
        for query in self.inflight.all():
            for task in (query.loop_task, query.attempt_task):
                if task is not None:
                    with suppress(asyncio.CancelledError):
                        await task
        for job in jobs:
            with suppress(asyncio.CancelledError):
                await job.task
        if self._transport is not None:
            self._transport.close()
