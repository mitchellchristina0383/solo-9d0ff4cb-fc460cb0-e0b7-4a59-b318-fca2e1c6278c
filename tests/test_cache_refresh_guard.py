#!/usr/bin/env python3
"""Unit tests for the cache identity guard behind background refreshes.

These exercise :class:`DNSCache` directly, without sockets or an event loop,
to pin down the "late refresh result must never be written back" semantics:

* a refresh replaces the entry only while the original entry is still alive
  and is still the current entry for the key (same entry id);
* a flush, a rule-change eviction, an expiry or a prior replacement all break
  the identity and make the refresh a no-op;
* uncachable refresh replies keep the original entry and its expiry.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RCODE, RR, SOA  # noqa: E402

from dns_forwarder.cache import DNSCache  # noqa: E402


def a_reply(qname: str, address: str, ttl: int, rcode: int = RCODE.NOERROR) -> DNSRecord:
    header = DNSHeader(id=1, qr=1, aa=1, ra=1)
    record = DNSRecord(header=header, q=DNSRecord.question(qname).q)
    if rcode == RCODE.NOERROR:
        record.add_answer(RR(qname, QTYPE.A, rdata=A(address), ttl=ttl))
    return record


def nxdomain_with_soa(qname: str, ttl: int = 60, minimum: int = 20) -> DNSRecord:
    header = DNSHeader(id=1, qr=1, aa=1, ra=1)
    record = DNSRecord(header=header, q=DNSRecord.question(qname).q)
    record.header.rcode = RCODE.NXDOMAIN
    soa = SOA(mname="ns1.example.com", rname="admin.example.com",
              times=(1, 7200, 3600, 1209600, minimum))
    record.add_auth(RR(qname, QTYPE.SOA, rdata=soa, ttl=ttl))
    return record


def main() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        print(("  PASS  " if cond else "  FAIL  ") + name + (f" {detail}" if detail and not cond else ""))
        if not cond:
            failures.append(name)

    cache = DNSCache()
    qname = "host.lab.example.com."

    # 1. Fresh store gets a unique id and a full TTL window.
    first = cache.store(a_reply(qname, "10.0.0.1", ttl=30), "upstream-a:5353")
    check("store returns an entry", first is not None)
    check("entry id is positive", first.entry_id > 0)
    check("entry is a positive A entry", not first.negative)
    first_id = first.entry_id

    # 2. Refresh while the same entry is live and current -> replaced.
    replacement = cache.apply_refresh(
        a_reply(qname, "10.0.0.2", ttl=30), "upstream-a:5353",
        qname=qname, qtype=QTYPE.A, entry_id=first_id,
    )
    check("matching refresh replaces the entry", replacement is not None)
    check("replacement gets a new identity", replacement.entry_id != first_id)
    current = cache.get_entry(qname, QTYPE.A)
    check("cache now holds the replacement", current.entry_id == replacement.entry_id)
    check("replacement carries the new TTL window", current.ttl == 30)

    # 3. A late result carrying the OLD id must be rejected.
    stale = cache.apply_refresh(
        a_reply(qname, "10.0.0.3", ttl=30), "upstream-a:5353",
        qname=qname, qtype=QTYPE.A, entry_id=first_id,
    )
    check("late refresh for a replaced entry is rejected", stale is None)
    check("rejected refresh did not change the cache",
          cache.get_entry(qname, QTYPE.A).entry_id == replacement.entry_id)

    # 4. Flush invalidates every outstanding refresh.
    cache.flush()
    rejected = cache.apply_refresh(
        a_reply(qname, "10.0.0.4", ttl=30), "upstream-a:5353",
        qname=qname, qtype=QTYPE.A, entry_id=replacement.entry_id,
    )
    check("refresh after flush is rejected", rejected is None)
    check("nothing resurrected by the late refresh", cache.get_entry(qname, QTYPE.A) is None)

    # 5. Rule-change eviction (invalidate_moved) invalidates identity too.
    entry = cache.store(a_reply(qname, "10.0.0.5", ttl=30), "upstream-a:5353")
    cache.invalidate_moved(
        {(qname, QTYPE.A): "upstream-a:5353"},
        lambda _name: "upstream-b:5353",
    )
    check("moved entry is evicted", cache.get_entry(qname, QTYPE.A) is None)
    rejected = cache.apply_refresh(
        a_reply(qname, "10.0.0.6", ttl=30), "upstream-a:5353",
        qname=qname, qtype=QTYPE.A, entry_id=entry.entry_id,
    )
    check("refresh of an evicted entry is rejected", rejected is None)

    # 6. Expired entry: refresh cannot resurrect it.
    expired = cache.store(a_reply(qname, "10.0.0.7", ttl=1), "upstream-a:5353")
    time.sleep(1.1)
    check("entry reports expired", cache.get(qname, QTYPE.A) is None)
    rejected = cache.apply_refresh(
        a_reply(qname, "10.0.0.8", ttl=30), "upstream-a:5353",
        qname=qname, qtype=QTYPE.A, entry_id=expired.entry_id,
    )
    check("refresh of an expired entry is rejected", rejected is None)
    check("expired entry stays gone", cache.get_entry(qname, QTYPE.A) is None)

    # 7. Uncachable refresh reply (TTL 0) keeps the original entry untouched.
    good = cache.store(a_reply(qname, "10.0.0.9", ttl=30), "upstream-a:5353")
    original_expiry = good.expires_at
    no_ttl = cache.apply_refresh(
        a_reply(qname, "10.0.0.10", ttl=0), "upstream-a:5353",
        qname=qname, qtype=QTYPE.A, entry_id=good.entry_id,
    )
    check("TTL-0 refresh reply is rejected", no_ttl is None)
    surviving = cache.get_entry(qname, QTYPE.A)
    check("original entry survives an uncachable refresh",
          surviving is not None and surviving.entry_id == good.entry_id)
    check("original expiry is preserved on refresh failure",
          surviving.expires_at == original_expiry)

    # 8. NXDOMAIN-with-SOA entries are negative and never early-refreshed by
    #    the service; the guard also rejects a positive answer carrying a
    #    negative entry's id.
    neg = cache.store(nxdomain_with_soa("gone.lab.example.com."), "upstream-a:5353")
    check("NXDOMAIN-with-SOA is cached as negative", neg is not None and neg.negative)
    rejected = cache.apply_refresh(
        a_reply("gone.lab.example.com.", "10.0.0.11", ttl=30),
        "upstream-a:5353", qname="gone.lab.example.com.", qtype=QTYPE.A,
        entry_id=neg.entry_id,
    )
    check("positive answer cannot replace via a negative entry id", rejected is None)

    print(f"\n=== cache guard: {8 - len(failures)}/8 groups passed ===")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
