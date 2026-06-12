# Collector agent (Phase 1): real dnsmasq + snmpd + passive scapy tap.
# Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsmasq \
        snmpd \
    && rm -rf /var/lib/apt/lists/*

# scapy for the passive packet tap (raw AF_PACKET sockets, no libpcap needed);
# kafka-python for the Kafka transport spine (TRANSPORT=kafka).
RUN pip install --no-cache-dir "scapy>=2.5" "kafka-python>=2.0"

WORKDIR /app

COPY shared/ ./shared/
COPY containers/collector/ ./collector/

# Service configs into their canonical locations.
COPY containers/collector/dnsmasq.conf /etc/dnsmasq.conf
COPY containers/collector/snmpd.conf /etc/snmp/snmpd.conf

# Run as a shell script so the execute bit / CRLF from a Windows host is irrelevant.
ENTRYPOINT ["sh", "/app/collector/entrypoint.sh"]
