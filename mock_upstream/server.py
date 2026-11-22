"""Configurable mock DNS upstream with controllable reply delays.

Runs a UDP DNS server (dnslib) and a small FastAPI control plane in the same
event loop. Two instances are deployed by docker-compose so the forwarder can
be pointed at either and rule changes can move names between them.

Capabilities needed by the test scenarios:

* per-name A records with explicit TTLs;
* NXDOMAIN replies carrying an SOA (RFC 2308 negative caching), optionally
  also NXDOMAIN *without* SOA to prove the forwarder does not cache those;
* per-name and global reply delays, implemented as scheduled ``sendto`` calls
  so a reply is still emitted after the forwarder has moved on (the forwarder
  must then drop it);
* query/reply counters over HTTP for assertions.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
from dataclasses import dataclass, field

import uvicorn
from fastapi import FastAPI, HTTPException
from dnslib import A, DNSHeader, DNSRecord, QTYPE, RCODE, RR, SOA

log = logging.getLogger("mock_upstream")


@dataclass
class RecordSpec:
    kind: str = "A"                     # "A" or "NXDOMAIN"
    ttl: int = 30
    addresses: list[str] = field(default_factory=list)
    # NXDOMAIN-only knobs
    zone: str | None = None
    soa_ttl: int = 60
    minimum: int = 30
    mname: str = "ns1.example.com"
    rname: str = "admin.example.com"
    include_soa: bool = True
    serial: int = 2026010100

    @classmethod
    def from_dict(cls, data: dict) -> "RecordSpec":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def _fqdn(name: str) -> str:
    """Normalize a DNS name to lower-case, dot-terminated wire form."""
    name = name.strip().lower()
    if not name:
        raise ValueError("empty DNS name")
    return name if name.endswith(".") else name + "."


class MockUpstream:
    def __init__(self, upstream_id: str) -> None:
        self.upstream_id = upstream_id
        self.records: dict[str, RecordSpec] = {}
        self.delays: dict[str, float] = {}
        self.default_delay = 0.0
        self.queries_received = 0
        self.replies_sent = 0
        self.by_name: dict[str, int] = {}
        self.transport: asyncio.DatagramTransport | None = None
        self._pending: set[asyncio.Task] = set()

    # ------------------------------------------------------------------ DNS
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.queries_received += 1
        try:
            request = DNSRecord.parse(data)
        except Exception:
            log.warning("unparseable query from %s", addr)
            return
        qname = str(request.q.qname).lower()
        self.by_name[qname] = self.by_name.get(qname, 0) + 1
        delay = self.delays.get(qname, self.default_delay)
        task = asyncio.ensure_future(self._delayed_reply(request, qname, addr, delay))
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    def error_received(self, exc: Exception) -> None:
        log.warning("upstream %s UDP error: %r", self.upstream_id, exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None:
            log.warning("upstream %s connection lost: %r", self.upstream_id, exc)

    async def _delayed_reply(
        self, request: DNSRecord, qname: str, addr, delay: float
    ) -> None:
        if delay:
            await asyncio.sleep(delay)
        try:
            reply = self.build_reply(request, qname)
            if self.transport is not None:
                self.transport.sendto(reply.pack(), addr)
                self.replies_sent += 1
        except Exception:
            log.exception("upstream %s failed building reply for %s",
                          self.upstream_id, qname)

    def build_reply(self, request: DNSRecord, qname: str) -> DNSRecord:
        header = DNSHeader(id=request.header.id, qr=1, aa=1, ra=1)
        reply = DNSRecord(header=header, q=request.q)
        spec = self._match(qname)
        if spec is None or spec.kind == "NXDOMAIN":
            reply.header.rcode = RCODE.NXDOMAIN
            if spec is not None and spec.include_soa:
                zone = spec.zone or qname
                soa = SOA(
                    mname=spec.mname,
                    rname=spec.rname,
                    times=(spec.serial, 7200, 3600, 1209600, spec.minimum),
                )
                reply.add_auth(RR(zone, QTYPE.SOA, rdata=soa, ttl=spec.soa_ttl))
            return reply

        for address in spec.addresses:
            reply.add_answer(
                RR(qname, QTYPE.A, rdata=A(address), ttl=spec.ttl)
            )
        return reply

    def _match(self, qname: str) -> RecordSpec | None:
        if qname in self.records:
            return self.records[qname]
        best: str | None = None
        for suffix in self.records:
            if qname == suffix or qname.endswith("." + suffix):
                if best is None or len(suffix) > len(best):
                    best = suffix
        return self.records.get(best)

    # --------------------------------------------------------------- config
    def load_zones(self, path: str) -> None:
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        self.default_delay = float(payload.get("default_delay", 0.0))
        for name, spec in payload.get("records", {}).items():
            self.records[_fqdn(name)] = RecordSpec.from_dict(spec)

    def counters(self) -> dict:
        return {
            "upstream_id": self.upstream_id,
            "queries_received": self.queries_received,
            "replies_sent": self.replies_sent,
            "by_name": dict(self.by_name),
            "pending_delayed": len(self._pending),
        }


def create_control_app(upstream: MockUpstream) -> FastAPI:
    app = FastAPI(title=f"Mock DNS upstream {upstream.upstream_id}", version="1.0.0")

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "upstream": upstream.upstream_id}

    @app.put("/records/{qname:path}")
    async def put_record(qname: str, spec: dict) -> dict:
        name = qname.lower().rstrip(".") + "."
        try:
            upstream.records[name] = RecordSpec.from_dict(spec)
        except TypeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "ok", "qname": name}

    @app.delete("/records/{qname:path}")
    async def delete_record(qname: str) -> dict:
        name = qname.lower().rstrip(".") + "."
        if name not in upstream.records:
            raise HTTPException(status_code=404, detail=name)
        del upstream.records[name]
        return {"status": "ok"}

    @app.post("/delay")
    async def set_delay(body: dict) -> dict:
        if "default" in body:
            upstream.default_delay = float(body["default"])
        for name, seconds in (body.get("qnames") or {}).items():
            normalized = name.lower().rstrip(".") + "."
            upstream.delays[normalized] = float(seconds)
        return {"status": "ok", "default_delay": upstream.default_delay,
                "delays": upstream.delays}

    @app.get("/counters")
    async def counters() -> dict:
        return upstream.counters()

    @app.post("/counters/reset")
    async def reset_counters() -> dict:
        upstream.queries_received = 0
        upstream.replies_sent = 0
        upstream.by_name.clear()
        return {"status": "ok"}

    @app.get("/records")
    async def list_records() -> dict:
        return {
            name: {
                "kind": spec.kind,
                "ttl": spec.ttl,
                "addresses": spec.addresses,
                "include_soa": spec.include_soa,
                "minimum": spec.minimum,
                "soa_ttl": spec.soa_ttl,
            }
            for name, spec in upstream.records.items()
        }

    return app


async def amain() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    upstream_id = os.environ.get("UPSTREAM_ID", "upstream")
    dns_host = os.environ.get("DNS_LISTEN_HOST", "0.0.0.0")
    dns_port = int(os.environ.get("DNS_LISTEN_PORT", "5353"))
    http_host = os.environ.get("HTTP_HOST", "0.0.0.0")
    http_port = int(os.environ.get("HTTP_PORT", "8090"))

    upstream = MockUpstream(upstream_id)
    zones_file = os.environ.get("ZONES_FILE")
    if zones_file and os.path.exists(zones_file):
        upstream.load_zones(zones_file)
        log.info("loaded %d records from %s", len(upstream.records), zones_file)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: upstream, local_addr=(dns_host, dns_port)
    )
    log.info("mock upstream %r DNS on :%d/udp, control on :%d",
             upstream_id, dns_port, http_port)

    server = uvicorn.Server(uvicorn.Config(
        create_control_app(upstream), host=http_host, port=http_port,
        log_level="warning", lifespan="off",
    ))
    server_task = asyncio.ensure_future(server.serve())

    stop_event = asyncio.Event()
    loop.add_signal_handler(signal.SIGTERM, stop_event.set)
    loop.add_signal_handler(signal.SIGINT, stop_event.set)
    try:
        await stop_event.wait()
    finally:
        server.should_exit = True
        await server_task
        transport.close()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
