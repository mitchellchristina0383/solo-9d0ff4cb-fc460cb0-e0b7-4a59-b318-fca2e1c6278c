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

from .cache import DNSCache
from .inflight import InflightQuery, InflightRegistry
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
    ) -> None:
        self.rules = rules
        self.cache = DNSCache()
        self.inflight = InflightRegistry()
        self.upstream_timeout = upstream_timeout
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
        host, _, port_s = upstream.rpartition(":")
        port = int(port_s)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        loop = asyncio.get_running_loop()
        protocol = _OneShotUDP(loop)
        # Retrieve any post-close exception (e.g. ICMP port unreachable) so the
        # garbage collector does not log an unretrieved future exception.
        protocol.reply.add_done_callback(lambda f: f.exception())
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol,
                remote_addr=(host, port),
            )
        except OSError as exc:
            log.warning("query#%d socket error for %s: %r", query.id, upstream, exc)
            return None
        try:
            transport.sendto(query.packet)
            # One socket per attempt: when the attempt is cancelled the
            # socket closes and any late datagram is dropped by the kernel.
            try:
                data = await asyncio.wait_for(protocol.reply, timeout=self.upstream_timeout)
            except asyncio.TimeoutError:
                self.stats.upstream_timeouts += 1
                log.warning("query#%d timeout waiting on %s", query.id, upstream)
                return None
            except Exception as exc:  # OSError, ICMP errors, ...
                log.warning("query#%d upstream I/O error %s: %r", query.id, upstream, exc)
                return None

            try:
                reply = DNSRecord.parse(data)
            except Exception:
                log.warning("query#%d unparseable reply from %s", query.id, upstream)
                return None
            if not reply.questions or str(reply.questions[0].qname).lower() != query.qname:
                log.warning("query#%d reply question mismatch from %s", query.id, upstream)
                return None
            return reply
        finally:
            transport.close()

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
        before = self.cache.snapshot_upstreams()
        evicted = self.cache.invalidate_moved(before, diff.new.match)

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
            "rule v%d applied: %d cache entries evicted, %d in-flight redispatched",
            diff.version, evicted, redispatched,
        )
        return {"version": diff.version, "cache_evicted": evicted,
                "inflight_redispatched": redispatched}

    async def shutdown(self) -> None:
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
        if self._transport is not None:
            self._transport.close()
