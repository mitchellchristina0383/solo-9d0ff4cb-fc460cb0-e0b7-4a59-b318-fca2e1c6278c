"""Entry point: one asyncio loop running the UDP listener and the HTTP API."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal

import uvicorn

from .api import create_app
from .models import Rule, RuleSet
from .rules import RuleStore
from .service import DNSForwarder

log = logging.getLogger("dns_forwarder")


def _load_initial_rules() -> RuleSet:
    default_upstream = os.environ.get("DEFAULT_UPSTREAM", "127.0.0.1:5301")
    rules_path = os.environ.get("RULES_FILE")
    rules: list[Rule] = []
    if rules_path and os.path.exists(rules_path):
        with open(rules_path, encoding="utf-8") as fh:
            payload = json.load(fh)
        rules = [Rule(**item) for item in payload.get("rules", [])]
    return RuleSet(default_upstream=default_upstream, rules=rules)


async def amain() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    listen_host = os.environ.get("DNS_LISTEN_HOST", "0.0.0.0")
    listen_port = int(os.environ.get("DNS_LISTEN_PORT", "53"))
    http_host = os.environ.get("HTTP_HOST", "0.0.0.0")
    http_port = int(os.environ.get("HTTP_PORT", "8080"))
    upstream_timeout = float(os.environ.get("UPSTREAM_TIMEOUT", "2.0"))

    initial = _load_initial_rules()
    rules = RuleStore(default_upstream=initial.default_upstream)
    rules.replace(initial)
    forwarder = DNSForwarder(rules, upstream_timeout=upstream_timeout)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: forwarder,
        local_addr=(listen_host, listen_port),
    )
    log.info("DNS forwarder listening on %s:%d/udp, default upstream %s",
             listen_host, listen_port, rules.default_upstream)

    app = create_app(rules, forwarder)
    config = uvicorn.Config(
        app, host=http_host, port=http_port, log_level="warning", lifespan="off"
    )
    server = uvicorn.Server(config)
    server_task = asyncio.ensure_future(server.serve())

    stop_event = asyncio.Event()
    loop.add_signal_handler(signal.SIGTERM, stop_event.set)
    loop.add_signal_handler(signal.SIGINT, stop_event.set)
    try:
        await stop_event.wait()
    finally:
        log.info("shutting down")
        server.should_exit = True
        await server_task
        await forwarder.shutdown()
        transport.close()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
