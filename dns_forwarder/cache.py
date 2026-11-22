"""DNS answer cache keyed by (qname, qtype).

Caching policy (deliberately narrow, per the service specification):

* Positive ``A`` answers (NOERROR with at least one A record) are cached for
  the minimum TTL found in the answer section.
* Negative ``NXDOMAIN`` replies are cached only when the authority section
  carries an SOA; per RFC 2308 the negative TTL is
  ``min(SOA record TTL, SOA MINIMUM field)``.
* Everything else (NODATA, SERVFAIL, malformed, TTL 0) is not cached.

Each entry remembers the upstream that produced it. A rule change only evicts
entries whose upstream *changed*; entries still served by the same upstream
keep their original expiry.

Every stored entry gets a unique, monotonic ``entry_id``. Background early
refreshes (see :mod:`dns_forwarder.refreshes`) carry the id of the entry that
triggered them; a refresh result is accepted only while that exact entry is
still the live, unexpired one for the key. A flush, an eviction after a rule
change or a normal replacement all change identity, so a late refresh result
can never be written back.
"""
from __future__ import annotations

import itertools
import time
from dataclasses import dataclass

from dnslib import DNSRecord, RCODE, RR, SOA
from dnslib.dns import QTYPE


@dataclass
class CacheEntry:
    qname: str
    qtype: int
    upstream: str
    raw: bytes
    rcode: int
    negative: bool
    stored_at: float          # time.monotonic() reference
    ttl: int                  # effective caching TTL in seconds
    expires_at: float         # time.monotonic() deadline
    entry_id: int = 0
    # Set once a background early-refresh has been scheduled for this entry,
    # so each cached answer triggers at most one refresh.
    refresh_scheduled: bool = False

    def alive(self, now: float) -> bool:
        return now < self.expires_at


class DNSCache:
    def __init__(self) -> None:
        self._entries: dict[tuple[str, int], CacheEntry] = {}
        self._id_counter = itertools.count(1)

    @staticmethod
    def _key(record: DNSRecord) -> tuple[str, int]:
        q = record.questions[0]
        return str(q.qname).lower(), getattr(q.qtype, "qtype", q.qtype)

    def get(self, qname: str, qtype: int, now: float | None = None) -> CacheEntry | None:
        now = time.monotonic() if now is None else now
        entry = self._entries.get((qname.lower(), qtype))
        if entry is None:
            return None
        if not entry.alive(now):
            self._entries.pop((qname.lower(), qtype), None)
            return None
        return entry

    def store(self, reply: DNSRecord, upstream: str, now: float | None = None) -> CacheEntry | None:
        """Store a reply if it matches the caching policy; return the entry."""
        now = time.monotonic() if now is None else now
        if not reply.questions:
            return None
        qname, qtype = self._key(reply)
        rcode = reply.header.rcode
        ttl: int | None = None
        negative = False

        if rcode == RCODE.NOERROR and qtype == QTYPE.A and reply.rr:
            ttl = min(int(rr.ttl) for rr in reply.rr)
        elif rcode == RCODE.NXDOMAIN:
            soa = self._find_soa(reply)
            if soa is None:
                return None
            minimum = int(soa.rdata.times[-1])
            ttl = min(int(soa.ttl), minimum)
            negative = True
        else:
            return None

        if ttl <= 0:
            return None

        entry = CacheEntry(
            qname=qname,
            qtype=qtype,
            upstream=upstream,
            raw=reply.pack(),
            rcode=rcode,
            negative=negative,
            stored_at=now,
            ttl=ttl,
            expires_at=now + ttl,
            entry_id=next(self._id_counter),
        )
        self._entries[(qname, qtype)] = entry
        return entry

    def get_entry(self, qname: str, qtype: int) -> CacheEntry | None:
        """Return the live entry for a key without expiry side effects."""
        entry = self._entries.get((qname.lower(), qtype))
        if entry is None:
            return None
        if not entry.alive(time.monotonic()):
            return None
        return entry

    def apply_refresh(
        self,
        reply: DNSRecord,
        upstream: str,
        *,
        qname: str,
        qtype: int,
        entry_id: int,
        now: float | None = None,
    ) -> CacheEntry | None:
        """Store a background-refresh reply behind an identity guard.

        The replacement happens only when:

        * the reply itself is complete and passes the normal caching policy
          (``store`` returns an entry; uncachable replies are rejected here);
        * the entry that triggered the refresh is still alive and is still the
          current entry for its key (same ``entry_id``).

        A flush, a rule-change eviction or any prior replacement changes the
        entry identity, so late refresh results are discarded rather than
        resurrecting or overwriting state.
        """
        now = time.monotonic() if now is None else now
        key = (qname.lower(), qtype)
        current = self._entries.get(key)
        # Early refresh only ever applies to positive A entries; a negative
        # entry must never be overwritten through the refresh path.
        if (
            current is None
            or current.negative
            or not current.alive(now)
            or current.entry_id != entry_id
        ):
            return None
        # Validate the reply against the caching policy first; if it is not
        # cacheable the current entry must keep its original expiry. The event
        # loop is single-threaded and there is no await between the guard and
        # the store, so the identity checked above cannot change in between.
        return self.store(reply, upstream, now=now)

    @staticmethod
    def _find_soa(reply: DNSRecord) -> RR | None:
        for rr in reply.auth:
            if getattr(rr.rtype, "rtype", rr.rtype) == QTYPE.SOA or isinstance(rr.rdata, SOA):
                return rr
        return None

    def invalidate_moved(self, old_upstream: dict[tuple[str, int], str], new_match) -> int:
        """Evict entries whose matched upstream differs under the new rules.

        ``old_upstream`` maps each cached key to the upstream that produced it
        (i.e. the old match). ``new_match`` is a callable qname -> upstream key.
        """
        removed = 0
        for key in list(self._entries):
            qname, _qtype = key
            if old_upstream.get(key) != new_match(qname):
                self._entries.pop(key, None)
                removed += 1
        return removed

    def snapshot_entries(self) -> dict[tuple[str, int], CacheEntry]:
        return dict(self._entries)

    def flush(self) -> int:
        count = len(self._entries)
        self._entries.clear()
        return count

    def entries(self) -> list[CacheEntry]:
        now = time.monotonic()
        return [e for e in self._entries.values() if e.alive(now)]

    def __len__(self) -> int:
        now = time.monotonic()
        return sum(1 for e in self._entries.values() if e.alive(now))
