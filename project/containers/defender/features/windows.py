"""Tumbling-window aggregation: CaptureEvent stream -> FeatureRecord stream.

Events are bucketed into fixed ``window_s`` tumbling windows keyed by
``(window_index, protocol, src)``. A window is *closed* (and its records emitted)
once an event from a strictly later window arrives, so late/out-of-order packets
within the current window are still counted. :meth:`flush_all` force-closes the
tail (used on shutdown / idle timeout) so the final partial window is not lost.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from shared.capture import DNS, SNMP, CaptureEvent
from shared.schema import FeatureRecord

from . import dns as dns_feats
from . import snmp as snmp_feats


class WindowAggregator:
    def __init__(self, window_s: float = 10.0) -> None:
        self.window_s = float(window_s)
        self._buckets: dict[int, list[CaptureEvent]] = defaultdict(list)
        self._max_index = -1
        self._closed_below = 0  # windows with index < this have been emitted

    def _index(self, ts: float) -> int:
        return int(ts // self.window_s)

    def add(self, event: CaptureEvent) -> list[FeatureRecord]:
        idx = self._index(event.ts)
        if idx < self._closed_below:
            return []  # late arrival for an already-emitted window; drop
        self._buckets[idx].append(event)
        self._max_index = max(self._max_index, idx)
        # Close every window strictly older than the newest one seen.
        out: list[FeatureRecord] = []
        for i in sorted(self._buckets):
            if i < self._max_index:
                out.extend(self._emit(i))
        return out

    def flush_all(self) -> list[FeatureRecord]:
        out: list[FeatureRecord] = []
        for i in sorted(self._buckets):
            out.extend(self._emit(i))
        return out

    def _emit(self, index: int) -> list[FeatureRecord]:
        events = self._buckets.pop(index)
        self._closed_below = max(self._closed_below, index + 1)
        window_start = index * self.window_s

        # Group by (protocol, src) -> one FeatureRecord per active host per window.
        groups: dict[tuple[str, str], list[CaptureEvent]] = defaultdict(list)
        for e in events:
            groups[(e.proto, e.src)].append(e)

        records: list[FeatureRecord] = []
        for (proto, src), evs in groups.items():
            dst = Counter(e.dst for e in evs).most_common(1)[0][0]
            if proto == DNS:
                feats, meta = dns_feats.extract(evs, self.window_s)
            elif proto == SNMP:
                feats, meta = snmp_feats.extract(evs, self.window_s)
            else:
                continue
            meta["window_start"] = window_start
            meta["window_seconds"] = self.window_s
            meta["event_count"] = len(evs)
            # Fraction of this host's packets that are responses. A server (e.g. the
            # collector) echoing an attack shows ~1.0; the initiating client ~0.0 —
            # detect mode uses this to avoid double-alerting on both halves of an
            # exchange (it suppresses response-dominated windows).
            meta["response_fraction"] = sum(e.is_response for e in evs) / len(evs)
            records.append(
                FeatureRecord(
                    protocol=proto,
                    ts=window_start,
                    src=src,
                    dst=dst,
                    features=feats,
                    meta=meta,
                )
            )
        return records
