FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY dns_forwarder /app/dns_forwarder
COPY mock_upstream /app/mock_upstream

# Role is selected by the compose command:
#   dns_forwarder.main      -> forwarding service (UDP 5300 + HTTP 8080)
#   mock_upstream.server    -> configurable mock upstream (UDP 5353 + HTTP 809x)
EXPOSE 5300/udp 8080 5353/udp 8090 8091
