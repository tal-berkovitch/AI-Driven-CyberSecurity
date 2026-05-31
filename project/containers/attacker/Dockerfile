# Attacker agent (Phase 1): realistic benign DNS + SNMP traffic generator.
# Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

# net-snmp client tools (snmpget / snmpgetnext / snmpbulkget) for real SNMP packets.
RUN apt-get update && apt-get install -y --no-install-recommends \
        snmp \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "dnspython>=2.6"

WORKDIR /app

COPY shared/ ./shared/
COPY containers/attacker/ ./attacker/

CMD ["python", "-m", "attacker.main"]
