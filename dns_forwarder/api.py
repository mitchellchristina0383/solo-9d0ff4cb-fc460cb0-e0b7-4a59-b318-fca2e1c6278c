"""FastAPI application exposing the rule-management API (see /docs and /redoc)."""
from __future__ import annotations

import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from dnslib import QTYPE

from .models import CacheEntryView, Rule, RuleSet, StatsView, normalize_suffix
from .rules import RuleStore
from .service import DNSForwarder

RCODE_NAMES = {
    0: "NOERROR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    5: "REFUSED",
}


def create_app(rules: RuleStore, forwarder: DNSForwarder) -> FastAPI:
    app = FastAPI(
        title="DNS Forwarder Control API",
        version="1.0.0",
        description=(
            "Manage UDP DNS forwarding rules. Rules use longest-DNS-suffix "
            "matching; names without a suffix match use the default upstream. "
            "Changes take effect immediately: cache entries for names whose "
            "upstream changed are evicted and in-flight queries are "
            "redispatched, without waiting for upstream answers."
        ),
    )

    def _state(request: Request) -> tuple[RuleStore, DNSForwarder]:
        return request.app.state.rules, request.app.state.forwarder

    app.state.rules = rules
    app.state.forwarder = forwarder

    @app.get("/rules", response_model=RuleSet, tags=["rules"],
             summary="Read the active rule set")
    async def get_rules(request: Request) -> RuleSet:
        store, _ = _state(request)
        return store.to_ruleset()

    @app.put("/rules", response_model=dict, tags=["rules"],
             summary="Atomically replace the whole rule set")
    async def replace_rules(body: RuleSet, request: Request) -> dict[str, Any]:
        store, fwd = _state(request)
        async with store.lock:
            diff = store.replace(body)
            effect = fwd.apply_diff(diff)
        return {"status": "ok", **effect}

    @app.post("/rules", response_model=dict, tags=["rules"],
              summary="Create or update one suffix rule",
              responses={400: {"description": "invalid rule"}})
    async def upsert_rule(rule: Rule, request: Request) -> dict[str, Any]:
        store, fwd = _state(request)
        async with store.lock:
            diff = store.upsert(rule)
            effect = fwd.apply_diff(diff)
        return {"status": "ok", **effect}

    @app.delete("/rules/{suffix:path}", response_model=dict, tags=["rules"],
                summary="Delete one suffix rule (the default cannot be deleted)")
    async def delete_rule(suffix: str, request: Request) -> dict[str, Any]:
        store, fwd = _state(request)
        try:
            normalized = normalize_suffix(suffix)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        async with store.lock:
            try:
                diff = store.delete(normalized)
            except KeyError as exc:
                raise HTTPException(status_code=404,
                                    detail=f"no rule for suffix {normalized!r}") from exc
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            effect = fwd.apply_diff(diff)
        return {"status": "ok", **effect}

    @app.get("/cache", response_model=list[CacheEntryView], tags=["cache"],
             summary="List live cache entries with remaining TTL")
    async def list_cache(request: Request) -> list[CacheEntryView]:
        _, fwd = _state(request)
        now = time.monotonic()
        return [
            CacheEntryView(
                qname=e.qname,
                qtype=QTYPE[e.qtype],
                upstream=e.upstream,
                rcode=RCODE_NAMES.get(e.rcode, str(e.rcode)),
                ttl_remaining=round(max(0.0, e.expires_at - now), 3),
                expires_at=round(e.expires_at, 3),
            )
            for e in fwd.cache.entries()
        ]

    @app.post("/cache/flush", response_model=dict, tags=["cache"],
              summary="Flush the whole cache")
    async def flush_cache(request: Request) -> dict[str, Any]:
        _, fwd = _state(request)
        return {"flushed": fwd.cache.flush()}

    @app.get("/inflight", tags=["inflight"],
             summary="List queries currently waiting on an upstream")
    async def list_inflight(request: Request) -> list[dict[str, Any]]:
        _, fwd = _state(request)
        now = time.monotonic()
        return [
            {
                "id": q.id,
                "qname": q.qname,
                "qtype": QTYPE[q.qtype],
                "upstream": q.upstream,
                "rule_version": q.rule_version,
                "attempts": q.attempts,
                "age_seconds": round(now - q.created_at, 3),
                "client": ":".join(map(str, q.client_addr)),
            }
            for q in fwd.inflight.all()
        ]

    @app.get("/stats", response_model=StatsView, tags=["observability"],
             summary="Counters and live state")
    async def get_stats(request: Request) -> StatsView:
        store, fwd = _state(request)
        s = fwd.stats
        return StatsView(
            queries_total=s.queries_total,
            cache_hits=s.cache_hits,
            upstream_queries=s.upstream_queries,
            redispatch_on_rule_change=s.redispatch_on_rule_change,
            attempts_cancelled=s.attempts_cancelled,
            stale_replies_discarded=s.stale_replies_discarded,
            servfail_responses=s.servfail_responses,
            upstream_timeouts=s.upstream_timeouts,
            in_flight=len(fwd.inflight),
            cache_entries=len(fwd.cache),
            upstreams=dict(store.matcher().suffix_upstreams)
                       | {"(default)": store.matcher().default_upstream},
        )

    @app.get("/health", tags=["observability"], summary="Liveness probe")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
