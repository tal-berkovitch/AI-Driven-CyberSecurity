#!/usr/bin/env sh
# Collector entrypoint: start the real resolver (dnsmasq) in the background, then
# run the passive packet tap in the foreground as the main process. If dnsmasq
# dies the tap stays up (acceptable for the lab); the whole container is recreated
# on `docker compose up` anyway.
set -e

# Start each run with a fresh capture topic so the defender doesn't re-ingest a
# previous run's packets (the file queue lives on a host bind mount).
rm -f /app/data/queue/capture.jsonl

echo "[entrypoint] starting dnsmasq (udp/53)"
dnsmasq --conf-file=/etc/dnsmasq.conf

echo "[entrypoint] starting passive sensor"
exec python -m collector.sensor
