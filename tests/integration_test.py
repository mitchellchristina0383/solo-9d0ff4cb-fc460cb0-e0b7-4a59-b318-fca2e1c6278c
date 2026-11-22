#!/usr/bin/env python3
"""End-to-end integration test for the DNS forwarding lab.

Spins up the real processes locally (no Docker required): two configurable
mock upstreams and the forwarder, then drives them over UDP and through the
HTTP rule API. Run with the project venv:

    .venv/bin/python tests/integration_test.py
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from dnslib import DNSRecord, QTYPE, RCODE

ROOT = Path(__file__).resolve().parents[1]

# High ports so the suite can run unprivileged outside Docker.
DNS_PORT = 15300
HTTP_PORT = 18080
A_DNS, A_HTTP = 15301, 18090
B_DNS, B_HTTP = 15302, 18091
BLACKHOLE = "127.0.0.1:1"
UPSTREAM_TIMEOUT = 1.5

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(f"{name} {detail}")
        print(f"  FAIL  {name} {detail}")


# -------------------------------------------------------------------- helpers
def dns_query(qname: str, server: str = "127.0.0.1", port: int = DNS_PORT,
              timeout: float = 4.0) -> DNSRecord:
    query = DNSRecord.question(qname, qtype="A")
    packet = query.pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(65535)
    finally:
        sock.close()
    return DNSRecord.parse(data)


def http(method: str, url: str, body: dict | None = None,
         expect_error: bool = False) -> tuple[int, dict | str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = resp.read()
            ctype = resp.headers.get_content_type()
            if ctype == "application/json":
                return resp.status, json.loads(payload) if payload else {}
            return resp.status, payload.decode(errors="replace")
    except urllib.error.HTTPError as exc:
        if not expect_error:
            raise
        payload = exc.read().decode()
        try:
            return exc.code, json.loads(payload)
        except json.JSONDecodeError:
            return exc.code, payload


def wait_http(url: str, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except OSError:
            time.sleep(0.2)
    return False


def rules_get() -> dict:
    _, body = http("GET", f"http://127.0.0.1:{HTTP_PORT}/rules")
    return body


def rules_replace(default: str, rules: list[dict]) -> dict:
    _, body = http("PUT", f"http://127.0.0.1:{HTTP_PORT}/rules",
                   {"default_upstream": default, "rules": rules})
    return body


def stats() -> dict:
    _, body = http("GET", f"http://127.0.0.1:{HTTP_PORT}/stats")
    return body


def upstream_counters(port: int) -> dict:
    _, body = http("GET", f"http://127.0.0.1:{port}/counters")
    return body


def set_delay(port: int, qnames: dict[str, float], default: float | None = None) -> None:
    body: dict = {"qnames": qnames}
    if default is not None:
        body["default"] = default
    http("POST", f"http://127.0.0.1:{port}/delay", body)


def answer_addresses(reply: DNSRecord) -> list[str]:
    return [str(rr.rdata) for rr in reply.rr
            if getattr(rr.rtype, "qtype", rr.rtype) == QTYPE.A]


def min_answer_ttl(reply: DNSRecord) -> int:
    ttls = [int(rr.ttl) for rr in reply.rr
            if getattr(rr.rtype, "qtype", rr.rtype) == QTYPE.A]
    return min(ttls) if ttls else -1


def cache_view() -> dict[str, dict]:
    _, entries = http("GET", f"http://127.0.0.1:{HTTP_PORT}/cache")
    return {e["qname"]: e for e in entries}


def refreshes_view() -> list[dict]:
    _, jobs = http("GET", f"http://127.0.0.1:{HTTP_PORT}/refreshes")
    return jobs


def put_record(port: int, qname: str, spec: dict) -> None:
    http("PUT", f"http://127.0.0.1:{port}/records/{qname.rstrip('.')}", spec)


def wait_until(predicate, timeout: float = 5.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# ----------------------------------------------------------------- processes
def start_processes() -> list[subprocess.Popen]:
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    common = [sys.executable, "-m"]
    procs: list[subprocess.Popen] = []

    procs.append(subprocess.Popen(
        common + ["mock_upstream.server"],
        cwd=ROOT, env={**env,
                       "UPSTREAM_ID": "upstream-a",
                       "DNS_LISTEN_PORT": str(A_DNS),
                       "HTTP_PORT": str(A_HTTP),
                       "ZONES_FILE": str(ROOT / "mock_upstream/zones-a.json")},
        stdout=open("/tmp/upstream-a.log", "w"),
        stderr=subprocess.STDOUT,
    ))
    procs.append(subprocess.Popen(
        common + ["mock_upstream.server"],
        cwd=ROOT, env={**env,
                       "UPSTREAM_ID": "upstream-b",
                       "DNS_LISTEN_PORT": str(B_DNS),
                       "HTTP_PORT": str(B_HTTP),
                       "ZONES_FILE": str(ROOT / "mock_upstream/zones-b.json")},
        stdout=open("/tmp/upstream-b.log", "w"),
        stderr=subprocess.STDOUT,
    ))
    procs.append(subprocess.Popen(
        common + ["dns_forwarder.main"],
        cwd=ROOT, env={**env,
                       "DNS_LISTEN_PORT": str(DNS_PORT),
                       "HTTP_PORT": str(HTTP_PORT),
                       "UPSTREAM_TIMEOUT": str(UPSTREAM_TIMEOUT),
                       # Production default is 0.2; the suite raises the
                       # refresh window so early-refresh scenarios stay fast
                       # and deterministic without forging tiny-TTL records.
                       "REFRESH_TTL_RATIO": "0.8",
                       "DEFAULT_UPSTREAM": f"127.0.0.1:{A_DNS}",
                       "RULES_FILE": str(ROOT / "config/initial-rules-local.json")},
        stdout=open("/tmp/forwarder.log", "w"),
        stderr=subprocess.STDOUT,
    ))
    return procs


def stop_processes(procs: list[subprocess.Popen]) -> None:
    for proc in procs:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
    deadline = time.monotonic() + 5
    for proc in procs:
        remaining = max(0.1, deadline - time.monotonic())
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            proc.kill()


# --------------------------------------------------------------------- tests
def test_basic_and_longest_suffix() -> None:
    print("\n[T1] forwarding + longest-suffix matching + docs")
    # initial-rules.json points lab.example.com at upstream A
    reply = dns_query("host1.lab.example.com.")
    check("A query answered NOERROR", reply.header.rcode == RCODE.NOERROR,
          f"rcode={reply.header.rcode}")
    check("answer comes from upstream A",
          answer_addresses(reply) == ["10.10.0.11"], str(answer_addresses(reply)))
    check("upstream A recorded one query",
          upstream_counters(A_HTTP)["by_name"].get("host1.lab.example.com.") == 1)
    check("upstream B received nothing",
          "host1.lab.example.com." not in upstream_counters(B_HTTP)["by_name"])

    # add a more specific suffix -> B must win for that name
    rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
        {"suffix": "host1.lab.example.com", "upstream": f"127.0.0.1:{B_DNS}"},
    ])
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    reply = dns_query("host1.lab.example.com.")
    check("longest suffix wins (host1 -> B)",
          answer_addresses(reply) == ["10.20.0.11"], str(answer_addresses(reply)))
    reply = dns_query("host2.lab.example.com.")
    check("shorter suffix still applies (host2 -> A)",
          answer_addresses(reply) == ["10.10.0.12"], str(answer_addresses(reply)))

    # unknown name falls through to the default upstream (A has no record -> NXDOMAIN)
    reply = dns_query("unknown.example.org.")
    check("no suffix match -> default upstream answers",
          reply.header.rcode == RCODE.NXDOMAIN, f"rcode={reply.header.rcode}")

    # OpenAPI docs are served
    code, _ = http("GET", f"http://127.0.0.1:{HTTP_PORT}/docs")
    check("GET /docs -> 200", code == 200, f"code={code}")
    code, body = http("GET", f"http://127.0.0.1:{HTTP_PORT}/openapi.json")
    check("openapi.json advertises rule endpoints",
          code == 200 and "/rules" in body["paths"])


def test_caching_policy() -> None:
    print("\n[T2] positive A caching, TTL countdown, negative caching")
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])

    reply1 = dns_query("host2.lab.example.com.")
    ttl_first = min_answer_ttl(reply1)
    before = upstream_counters(A_HTTP)["by_name"]["host2.lab.example.com."]
    time.sleep(1.1)
    reply2 = dns_query("host2.lab.example.com.")
    after = upstream_counters(A_HTTP)["by_name"]["host2.lab.example.com."]
    check("second query served from cache", before == after,
          f"before={before} after={after}")
    check("cached TTL counts down", min_answer_ttl(reply2) < ttl_first,
          f"{min_answer_ttl(reply2)} vs {ttl_first}")
    check("stats cache_hits increments", stats()["cache_hits"] >= 1)

    # NXDOMAIN with SOA is cached (negative TTL = min(SOA TTL, minimum)=20)
    reply = dns_query("gone.lab.example.com.")
    check("NXDOMAIN returned", reply.header.rcode == RCODE.NXDOMAIN)
    check("NXDOMAIN authority carries SOA",
          any(getattr(rr.rtype, "rtype", rr.rtype) == QTYPE.SOA for rr in reply.auth))
    before = upstream_counters(A_HTTP)["by_name"]["gone.lab.example.com."]
    dns_query("gone.lab.example.com.")
    after = upstream_counters(A_HTTP)["by_name"]["gone.lab.example.com."]
    check("NXDOMAIN-with-SOA is cached", before == after)
    _, cache = http("GET", f"http://127.0.0.1:{HTTP_PORT}/cache")
    check("cache view shows negative entry",
          any(e["qname"] == "gone.lab.example.com." and e["rcode"] == "NXDOMAIN"
              for e in cache))

    # NXDOMAIN without SOA must NOT be cached
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    dns_query("no-soa.lab.example.com.")
    dns_query("no-soa.lab.example.com.")
    count = upstream_counters(A_HTTP)["by_name"]["no-soa.lab.example.com."]
    check("NXDOMAIN without SOA is not cached", count == 2, f"count={count}")

    # TTL expiry forces re-query (short.lab.example.com TTL=2)
    reply = dns_query("short.lab.example.com.")
    check("short-TTL answer ok", reply.header.rcode == RCODE.NOERROR)
    before = upstream_counters(A_HTTP)["by_name"]["short.lab.example.com."]
    time.sleep(2.3)
    dns_query("short.lab.example.com.")
    after = upstream_counters(A_HTTP)["by_name"]["short.lab.example.com."]
    check("entry expires after its TTL", after == before + 1,
          f"before={before} after={after}")


def test_rule_change_invalidation() -> None:
    print("\n[T3] rule change: moved names evicted, unchanged names keep cache")
    rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "host2.lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")

    # populate cache for two names, capture TTL and time
    dns_query("host1.lab.example.com.")
    dns_query("host2.lab.example.com.")
    _, cache_before = http("GET", f"http://127.0.0.1:{HTTP_PORT}/cache")
    names = {e["qname"]: e for e in cache_before}
    check("both names cached first",
          "host1.lab.example.com." in names and "host2.lab.example.com." in names,
          json.dumps(cache_before))
    ttl_before = names["host1.lab.example.com."]["ttl_remaining"]
    time.sleep(1.0)

    # move only host2 (more specific suffix) to B; host1 stays on A
    effect = rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "host2.lab.example.com", "upstream": f"127.0.0.1:{B_DNS}"},
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])
    check("PUT /rules reports one eviction", effect["cache_evicted"] == 1,
          json.dumps(effect))
    _, cache_after = http("GET", f"http://127.0.0.1:{HTTP_PORT}/cache")
    names_after = {e["qname"]: e for e in cache_after}
    check("moved name evicted", "host2.lab.example.com." not in names_after)
    check("unchanged name retained", "host1.lab.example.com." in names_after)
    check("retained entry keeps its original expiry window",
          names_after["host1.lab.example.com."]["ttl_remaining"] <= ttl_before - 0.5,
          f"before={ttl_before} after={names_after['host1.lab.example.com.']['ttl_remaining']}")

    # moved name now answers from B without any old cache
    reply = dns_query("host2.lab.example.com.")
    check("moved name answers from new upstream B",
          answer_addresses(reply) == ["10.20.0.12"], str(answer_addresses(reply)))
    check("B received the query",
          upstream_counters(B_HTTP)["by_name"].get("host2.lab.example.com.") == 1)
    # unchanged name still hits old cache: A counters must not move
    a_before = upstream_counters(A_HTTP)["by_name"].get("host1.lab.example.com.", 0)
    dns_query("host1.lab.example.com.")
    a_after = upstream_counters(A_HTTP)["by_name"].get("host1.lab.example.com.", 0)
    check("unchanged name still hits original cache", a_before == a_after)


def test_inflight_redispatch() -> None:
    print("\n[T4] in-flight query redispatched, late old reply discarded")
    rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    http("POST", f"http://127.0.0.1:{A_HTTP}/counters/reset")
    http("POST", f"http://127.0.0.1:{B_HTTP}/counters/reset")
    # A will answer slowly; B answers immediately
    set_delay(A_HTTP, {"slow.lab.example.com.": 1.2})

    import threading
    result: dict = {}

    def issue() -> None:
        result["reply"] = dns_query("slow.lab.example.com.", timeout=5)

    worker = threading.Thread(target=issue)
    worker.start()
    time.sleep(0.4)  # let the forwarder send to A and park waiting
    _, inflight = http("GET", f"http://127.0.0.1:{HTTP_PORT}/inflight")
    check("query is in flight via A",
          any(q["qname"] == "slow.lab.example.com." and
              q["upstream"].endswith(str(A_DNS)) for q in inflight),
          json.dumps(inflight))

    effect = rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{B_DNS}"},
    ])
    check("rule change redispatches the in-flight query",
          effect["inflight_redispatched"] == 1 and effect["cache_evicted"] == 0,
          json.dumps(effect))
    check("cancellation counter incremented",
          stats()["attempts_cancelled"] >= 1)

    worker.join(timeout=5)
    check("client gets an answer after redispatch", "reply" in result)
    if "reply" in result:
        check("answer comes from B, not the slow A reply",
              answer_addresses(result["reply"]) == ["10.20.0.99"],
              str(answer_addresses(result["reply"])))

    # A's late reply was emitted into a closed attempt socket and cannot
    # reach the client; B served exactly one query for this name.
    time.sleep(1.2)
    check("A did emit its late reply (but it had to be dropped)",
          upstream_counters(A_HTTP)["replies_sent"] >= 1,
          json.dumps(upstream_counters(A_HTTP)))
    check("B served the redispatched query",
          upstream_counters(B_HTTP)["by_name"].get("slow.lab.example.com.") == 1,
          json.dumps(upstream_counters(B_HTTP)))
    check("no in-flight queries remain", len(stats() and http(
        "GET", f"http://127.0.0.1:{HTTP_PORT}/inflight")[1]) == 0)


def test_servfail_on_upstream_failure() -> None:
    print("\n[T5] unreachable / silent upstream -> SERVFAIL")
    # 5a) hard failure: nothing listens, the socket gets an immediate error
    rules_replace(BLACKHOLE, [
        {"suffix": "lab.example.com", "upstream": BLACKHOLE},
    ])
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    start = time.monotonic()
    reply = dns_query("host1.lab.example.com.", timeout=UPSTREAM_TIMEOUT + 3)
    elapsed = time.monotonic() - start
    check("dead upstream yields SERVFAIL", reply.header.rcode == RCODE.SERVFAIL,
          f"rcode={reply.header.rcode}")
    check("hard failure returns fast, no busy retry", elapsed <= UPSTREAM_TIMEOUT,
          f"elapsed={elapsed:.2f}s")
    check("servfail counter incremented", stats()["servfail_responses"] >= 1)
    check("SERVFAIL is not cached",
          len(http("GET", f"http://127.0.0.1:{HTTP_PORT}/cache")[1]) == 0)

    # 5b) timeout: the upstream accepts the datagram but stays silent
    rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    set_delay(A_HTTP, {"silent.lab.example.com.": UPSTREAM_TIMEOUT + 3.0})
    start = time.monotonic()
    reply = dns_query("silent.lab.example.com.", timeout=UPSTREAM_TIMEOUT + 3)
    elapsed = time.monotonic() - start
    check("silent upstream yields SERVFAIL after the timeout",
          reply.header.rcode == RCODE.SERVFAIL, f"rcode={reply.header.rcode}")
    check("elapsed time is about one configured timeout",
          UPSTREAM_TIMEOUT - 0.2 <= elapsed <= UPSTREAM_TIMEOUT + 1.0,
          f"elapsed={elapsed:.2f}s")
    check("timeout counter incremented", stats()["upstream_timeouts"] >= 1)


def test_api_validation() -> None:
    print("\n[T6] API validation and single-rule endpoints")
    code, body = http("PUT", f"http://127.0.0.1:{HTTP_PORT}/rules",
                      {"default_upstream": "", "rules": []}, expect_error=True)
    check("empty default upstream rejected", code == 422, str(body)[:120])
    code, body = http("POST", f"http://127.0.0.1:{HTTP_PORT}/rules",
                      {"suffix": "lab.example.com", "upstream": "not a host:abc"},
                      expect_error=True)
    check("non-numeric port rejected", code == 422)
    code, _ = http("POST", f"http://127.0.0.1:{HTTP_PORT}/rules",
                   {"suffix": "newzone.example.com",
                    "upstream": f"127.0.0.1:{B_DNS}"})
    check("POST single rule -> 200", code == 200)
    current = rules_get()
    check("new rule visible", any(r["suffix"] == "newzone.example.com."
                                  for r in current["rules"]))
    code, _ = http("DELETE",
                   f"http://127.0.0.1:{HTTP_PORT}/rules/newzone.example.com")
    check("DELETE rule -> 200", code == 200)
    code, _ = http("DELETE",
                   f"http://127.0.0.1:{HTTP_PORT}/rules/newzone.example.com",
                   expect_error=True)
    check("DELETE missing rule -> 404", code == 404)


def test_interleaved_updates_and_queries() -> None:
    print("\n[T7] interleaved rule updates and DNS queries")
    rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    http("POST", f"http://127.0.0.1:{A_HTTP}/counters/reset")
    http("POST", f"http://127.0.0.1:{B_HTTP}/counters/reset")

    import threading
    stop = threading.Event()
    errors: list[str] = []

    def query_worker() -> None:
        names = ["host1.lab.example.com.", "host2.lab.example.com.",
                 "short.lab.example.com."]
        idx = 0
        while not stop.is_set():
            try:
                reply = dns_query(names[idx % len(names)], timeout=3)
                if reply.header.rcode not in (RCODE.NOERROR, RCODE.NXDOMAIN):
                    errors.append(f"unexpected rcode {reply.header.rcode}")
            except OSError as exc:
                errors.append(f"query error: {exc}")
            idx += 1

    def rule_worker() -> None:
        toggle = 0
        while not stop.is_set():
            upstream = f"127.0.0.1:{A_DNS}" if toggle % 2 == 0 else f"127.0.0.1:{B_DNS}"
            try:
                rules_replace(f"127.0.0.1:{A_DNS}", [
                    {"suffix": "lab.example.com", "upstream": upstream},
                ])
            except OSError as exc:
                errors.append(f"rule error: {exc}")
            toggle += 1
            time.sleep(0.05)

    qt = threading.Thread(target=query_worker)
    rt = threading.Thread(target=rule_worker)
    qt.start(); rt.start()
    time.sleep(6)
    stop.set()
    qt.join(timeout=5); rt.join(timeout=5)

    check("no query/rule errors during interleaving", not errors, str(errors[:3]))
    final = rules_get()
    final_up = final["rules"][0]["upstream"]
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    reply = dns_query("host1.lab.example.com.")
    expected = "10.10.0.11" if final_up.endswith(str(A_DNS)) else "10.20.0.11"
    check("final rule set is consistently honoured",
          answer_addresses(reply) == [expected],
          f"rule={final_up} got={answer_addresses(reply)}")
    check("both upstreams were exercised",
          upstream_counters(A_HTTP)["queries_received"] > 0
          and upstream_counters(B_HTTP)["queries_received"] > 0)


def test_early_refresh_concurrent_hits() -> None:
    print("\n[T8a] early refresh: concurrent hits, one refresh, fresh TTL")
    qname = "host1.lab.example.com."
    rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    http("POST", f"http://127.0.0.1:{A_HTTP}/counters/reset")
    # A short delay on A keeps the background refresh observable in /refreshes.
    set_delay(A_HTTP, {qname: 0.8})
    put_record(A_HTTP, qname, {"kind": "A", "ttl": 10, "addresses": ["10.10.0.11"]})

    # Prime the cache (the priming foreground query waits out the 0.8s delay).
    first = dns_query(qname, timeout=4)
    check("priming query answered", first.header.rcode == RCODE.NOERROR)
    entry_before = cache_view()[qname]
    check("primed entry visible in /cache", entry_before["ttl_original"] == 10)
    check("no refresh scheduled yet (full TTL)",
          entry_before["refresh_scheduled"] is False)
    upstream_before = upstream_counters(A_HTTP)["by_name"].get(qname, 0)

    # Advance into the last 20% of the TTL window (the suite ratio is 0.8).
    time.sleep(8.2)

    # The first hit in the window schedules exactly one background refresh.
    dns_query(qname)
    view = cache_view().get(qname)
    check("cache marks the entry as refresh-scheduled",
          view is not None and view["refresh_scheduled"] is True, json.dumps(view))
    check("one refresh job is visible via /refreshes",
          wait_until(lambda: any(j["qname"] == qname for j in refreshes_view())),
          json.dumps(refreshes_view()))

    # While the refresh is pending, a burst of concurrent clients is answered
    # immediately from the same cached entry, with no extra jobs or datagrams.
    import threading
    replies: list[DNSRecord] = []
    errors: list[str] = []

    def client() -> None:
        try:
            replies.append(dns_query(qname, timeout=3))
        except OSError as exc:  # pragma: no cover - failure path
            errors.append(str(exc))

    threads = [threading.Thread(target=client) for _ in range(8)]
    burst_start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    burst_elapsed = time.monotonic() - burst_start

    check("all concurrent clients got a reply",
          len(replies) == 8 and not errors, f"replies={len(replies)} {errors}")
    check("cached answers come back immediately (<200ms, no upstream wait)",
          burst_elapsed < 0.2, f"elapsed={burst_elapsed:.3f}s")
    check("every burst answer carries the cached address",
          all(answer_addresses(r) == ["10.10.0.11"] for r in replies))
    check("concurrent hits never schedule a second refresh job",
          len([j for j in refreshes_view() if j["qname"] == qname]) == 1,
          json.dumps(refreshes_view()))
    check("no extra upstream datagram while the refresh is pending",
          upstream_counters(A_HTTP)["by_name"].get(qname, 0)
          == upstream_before + 1)

    # The background refresh finishes and replaces the entry with a fresh
    # full-TTL one (a new entry id); one extra upstream query served everyone.
    replaced = wait_until(
        lambda: (e := cache_view().get(qname)) is not None
        and e["entry_id"] != entry_before["entry_id"]
        and e["ttl_remaining"] > 8.0
    )
    check("refresh replaced the entry with a fresh full-TTL one", replaced,
          json.dumps(cache_view().get(qname)))
    upstream_after = upstream_counters(A_HTTP)["by_name"].get(qname, 0)
    check("the whole burst triggered exactly one upstream refresh",
          upstream_after == upstream_before + 1,
          f"before={upstream_before} after={upstream_after}")
    s = stats()
    check("stats count one triggered and one succeeded refresh",
          s["refreshes_triggered"] >= 1 and s["refreshes_succeeded"] >= 1,
          json.dumps(s))

    # Hits on the young replacement stay served from cache and do not refresh.
    dns_query(qname)
    dns_query(qname)
    check("no further upstream queries while the fresh entry is young",
          upstream_counters(A_HTTP)["by_name"].get(qname, 0) == upstream_after)
    check("refresh list empties once the job finishes",
          wait_until(lambda: all(j["qname"] != qname for j in refreshes_view())))
    set_delay(A_HTTP, {qname: 0.0})


def test_early_refresh_failure_keeps_expiry() -> None:
    print("\n[T8b] early refresh failure keeps the original expiry, then normal re-query")
    qname = "host2.lab.example.com."
    rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    http("POST", f"http://127.0.0.1:{A_HTTP}/counters/reset")
    # TTL 15 keeps the entry alive across the 1.5s refresh timeout below.
    put_record(A_HTTP, qname, {"kind": "A", "ttl": 15, "addresses": ["10.10.0.12"]})

    dns_query(qname)
    entry_before = cache_view()[qname]
    expiry_before = entry_before["expires_at"]

    # Make the upstream silent for this name: the refresh must time out.
    set_delay(A_HTTP, {qname: UPSTREAM_TIMEOUT + 3.0})
    time.sleep(12.2)  # cross the 80% refresh mark (TTL 15 -> window at 3s left)
    dns_query(qname)  # triggers the background refresh
    check("refresh job appears",
          wait_until(lambda: any(j["qname"] == qname for j in refreshes_view())))

    failed = wait_until(
        lambda: stats()["refreshes_failed"] >= 1,
        timeout=UPSTREAM_TIMEOUT + 2.0,
    )
    check("refresh failure is counted", failed, json.dumps(stats()))
    view = cache_view().get(qname)
    check("original entry survives the failed refresh",
          view is not None and view["entry_id"] == entry_before["entry_id"],
          json.dumps(view))
    check("original expiry is untouched after refresh failure",
          view is not None and abs(view["expires_at"] - expiry_before) < 0.05,
          f"before={expiry_before} after={view and view['expires_at']}")
    check("failed refresh does not reschedule itself",
          all(j["qname"] != qname for j in refreshes_view()))

    # Once the entry really expires, a normal query goes back to the upstream.
    # Restore a fast answer first so this foreground query succeeds.
    set_delay(A_HTTP, {qname: 0.0})
    time.sleep(2.0)
    check("entry has expired out of the cache view", qname not in cache_view())
    before = upstream_counters(A_HTTP)["by_name"].get(qname, 0)
    reply = dns_query(qname)
    after = upstream_counters(A_HTTP)["by_name"].get(qname, 0)
    check("post-expiry query re-queries the upstream as usual",
          reply.header.rcode == RCODE.NOERROR and after == before + 1,
          f"before={before} after={after}")


def test_early_refresh_flush_and_reroute() -> None:
    print("\n[T8c] flush/reroute during a refresh: late result never written back")
    rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    http("POST", f"http://127.0.0.1:{A_HTTP}/counters/reset")
    http("POST", f"http://127.0.0.1:{B_HTTP}/counters/reset")

    # --- phase 1: flush while a refresh is in flight ----------------------
    flush_name = "flushcheck.lab.example.com."
    put_record(A_HTTP, flush_name, {"kind": "A", "ttl": 10, "addresses": ["10.10.0.71"]})
    set_delay(A_HTTP, {flush_name: 0.8})

    dns_query(flush_name, timeout=4)
    entry_before = cache_view()[flush_name]
    time.sleep(8.2)  # enter the refresh window (ratio 0.8)
    dns_query(flush_name)
    check("[flush] refresh in flight before flush",
          wait_until(lambda: any(j["qname"] == flush_name for j in refreshes_view())))

    _, body = http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    check("[flush] flush reports the cleared entry",
          body.get("flushed", 0) >= 1, json.dumps(body))
    check("[flush] flush cancels the refresh job",
          wait_until(lambda: all(j["qname"] != flush_name for j in refreshes_view())))

    # Long enough for the (cancelled) upstream answer to have landed: the
    # entry-id guard must keep it out of the cache.
    time.sleep(1.5)
    check("[flush] late refresh result is not resurrected after flush",
          cache_view().get(flush_name) is None, json.dumps(cache_view()))
    check("[flush] cancelled refresh is counted",
          stats()["refreshes_cancelled"] >= 1, json.dumps(stats()))

    # --- phase 2: reroute while a refresh is in flight --------------------
    reroute_name = "reroutecheck.lab.example.com."
    put_record(A_HTTP, reroute_name, {"kind": "A", "ttl": 10, "addresses": ["10.10.0.72"]})
    put_record(B_HTTP, reroute_name, {"kind": "A", "ttl": 10, "addresses": ["10.20.0.72"]})
    set_delay(A_HTTP, {reroute_name: 0.8})

    dns_query(reroute_name, timeout=4)
    reroute_entry = cache_view()[reroute_name]
    check("[reroute] entry cached via A first", reroute_entry is not None)
    time.sleep(8.2)  # enter the refresh window again
    dns_query(reroute_name)
    check("[reroute] refresh in flight before reroute",
          wait_until(lambda: any(j["qname"] == reroute_name for j in refreshes_view())))

    effect = rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{B_DNS}"},
    ])
    check("[reroute] rule change evicts the entry and cancels its refresh",
          effect["cache_evicted"] >= 1 and effect["refreshes_cancelled"] >= 1,
          json.dumps(effect))
    check("[reroute] entry gone after reroute", cache_view().get(reroute_name) is None)
    check("[reroute] no refresh survives the reroute",
          all(j["qname"] != reroute_name for j in refreshes_view()))

    time.sleep(1.5)  # let A's late reply land on the closed socket
    check("[reroute] A's late refresh result is not cached",
          cache_view().get(reroute_name) is None, json.dumps(cache_view()))
    reply = dns_query(reroute_name)  # normal miss -> B answers immediately
    check("[reroute] next query is served by the new upstream B",
          answer_addresses(reply) == ["10.20.0.72"], str(answer_addresses(reply)))
    check("[reroute] cache entry now records B as its upstream",
          cache_view()[reroute_name]["upstream"].endswith(str(B_DNS)))

    set_delay(A_HTTP, {flush_name: 0.0, reroute_name: 0.0})


def test_early_refresh_survives_neutral_rule_update() -> None:
    print("\n[T8d] rule update that does not change the upstream keeps the refresh valid")
    qname = "neutral.lab.example.com."
    rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])
    http("POST", f"http://127.0.0.1:{HTTP_PORT}/cache/flush")
    http("POST", f"http://127.0.0.1:{A_HTTP}/counters/reset")
    put_record(A_HTTP, qname, {"kind": "A", "ttl": 10, "addresses": ["10.10.0.61"]})
    set_delay(A_HTTP, {qname: 0.8})

    dns_query(qname, timeout=4)
    entry_before = cache_view()[qname]
    time.sleep(8.2)  # enter the refresh window while the 0.8s refresh is observable
    dns_query(qname)  # schedules the refresh (A answers after 0.8s)
    check("refresh scheduled via A",
          wait_until(lambda: any(
              j["qname"] == qname and j["upstream"].endswith(str(A_DNS))
              for j in refreshes_view())))

    # A neutral rewrite: the same selected upstream, expressed through an
    # equivalent rule set with an extra suffix. Nothing may be evicted/cancelled.
    effect = rules_replace(f"127.0.0.1:{A_DNS}", [
        {"suffix": "example.com", "upstream": f"127.0.0.1:{A_DNS}"},
        {"suffix": "lab.example.com", "upstream": f"127.0.0.1:{A_DNS}"},
    ])
    check("neutral rule update evicts nothing and cancels no refresh",
          effect["cache_evicted"] == 0 and effect["refreshes_cancelled"] == 0,
          json.dumps(effect))
    check("the same entry identity is retained",
          (e := cache_view().get(qname)) is not None
          and e["entry_id"] == entry_before["entry_id"], json.dumps(cache_view()))
    check("the refresh job keeps running against A",
          any(j["qname"] == qname for j in refreshes_view()),
          json.dumps(refreshes_view()))

    replaced = wait_until(
        lambda: (v := cache_view().get(qname)) is not None
        and v["entry_id"] != entry_before["entry_id"] and v["ttl_remaining"] > 8.0,
        timeout=4.0,
    )
    check("refresh still completes and replaces the entry after the rule update",
          replaced, json.dumps(cache_view().get(qname)))
    check("successful refresh counted", stats()["refreshes_succeeded"] >= 1)
    set_delay(A_HTTP, {qname: 0.0})


def main() -> int:
    procs = start_processes()
    try:
        healthy = all([
            wait_http(f"http://127.0.0.1:{A_HTTP}/health"),
            wait_http(f"http://127.0.0.1:{B_HTTP}/health"),
            wait_http(f"http://127.0.0.1:{HTTP_PORT}/health"),
        ])
        if not healthy:
            print("services failed to start; see /tmp/forwarder.log")
            return 2
        print("all three services healthy")
        test_basic_and_longest_suffix()
        test_caching_policy()
        test_rule_change_invalidation()
        test_inflight_redispatch()
        test_servfail_on_upstream_failure()
        test_api_validation()
        test_interleaved_updates_and_queries()
        test_early_refresh_concurrent_hits()
        test_early_refresh_failure_keeps_expiry()
        test_early_refresh_flush_and_reroute()
        test_early_refresh_survives_neutral_rule_update()
    finally:
        stop_processes(procs)

    print(f"\n=== {len(PASSED)} passed, {len(FAILED)} failed ===")
    for failure in FAILED:
        print(f"  - {failure}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
