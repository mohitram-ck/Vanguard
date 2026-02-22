"""
Vanguard NIDS — Feature Extraction Module
Converts raw PacketRecords into statistical ML-ready feature vectors
over a rolling time window using pandas and numpy.
"""

import logging
import queue
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from typing import Optional

import numpy as np
import pandas as pd

from vanguard.ingestion.packet_capture import PacketRecord

# ── Logging ────────────────────────────────────────────────────────────────────
logger = logging.getLogger("vanguard.features")


# ── Feature Extractor ──────────────────────────────────────────────────────────
class FeatureExtractor:
    """
    Consumes PacketRecord objects from the ingestion queue,
    buffers them in a rolling time window, and produces
    statistical feature vectors for the AI Engine.
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        output_queue: queue.Queue,
        window_seconds: int = 10,
        poll_interval: float = 1.0,
    ):
        """
        Args:
            packet_queue:    Input queue from the PacketCaptureEngine.
            output_queue:    Output queue to feed into the AI Engine.
            window_seconds:  Rolling time window size in seconds.
            poll_interval:   How often (seconds) to compute features.
        """
        self.packet_queue = packet_queue
        self.output_queue = output_queue
        self.window_seconds = window_seconds
        self.poll_interval = poll_interval

        self._buffer: deque[PacketRecord] = deque()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._vectors_produced = 0

    # ── Buffer Management ──────────────────────────────────────────────────────
    def _drain_queue(self) -> None:
        """Pull all available packets from the ingestion queue into buffer."""
        while True:
            try:
                record = self.packet_queue.get_nowait()
                self._buffer.append(record)
            except queue.Empty:
                break

    def _evict_old_packets(self) -> None:
        """Remove packets older than the rolling window."""
        cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
        while self._buffer and self._buffer[0].timestamp < cutoff:
            self._buffer.popleft()

    # ── Feature Computation ────────────────────────────────────────────────────
    def _compute_features(self) -> Optional[dict]:
        """
        Compute statistical features from packets in the current window.
        Returns None if the buffer is empty.
        """
        if not self._buffer:
            return None

        # Convert buffer to a DataFrame for easy computation
        records = list(self._buffer)
        df = pd.DataFrame([{
            "timestamp":    r.timestamp,
            "src_ip":       r.src_ip,
            "dst_ip":       r.dst_ip,
            "src_port":     r.src_port if r.src_port else 0,
            "dst_port":     r.dst_port if r.dst_port else 0,
            "protocol":     r.protocol,
            "payload_size": r.payload_size,
            "flags":        r.flags if r.flags else "",
        } for r in records])

        # ── Volume Features ────────────────────────────────────────────────────
        total_packets       = len(df)
        unique_src_ips      = df["src_ip"].nunique()
        unique_dst_ips      = df["dst_ip"].nunique()
        unique_dst_ports    = df["dst_port"].nunique()

        # ── Protocol Distribution ──────────────────────────────────────────────
        proto_counts        = df["protocol"].value_counts()
        tcp_count           = int(proto_counts.get("TCP", 0))
        udp_count           = int(proto_counts.get("UDP", 0))
        icmp_count          = int(proto_counts.get("ICMP", 0))
        tcp_ratio           = tcp_count / total_packets
        udp_ratio           = udp_count / total_packets

        # ── Payload Size Statistics ────────────────────────────────────────────
        payload             = df["payload_size"]
        payload_mean        = float(payload.mean())
        payload_std         = float(payload.std(ddof=0))
        payload_max         = float(payload.max())
        payload_min         = float(payload.min())
        payload_median      = float(payload.median())

        # ── Packet Rate ────────────────────────────────────────────────────────
        time_span = (
            df["timestamp"].max() - df["timestamp"].min()
        ).total_seconds()
        packet_rate = total_packets / time_span if time_span > 0 else float(total_packets)

        # ── Port Scan Heuristic ────────────────────────────────────────────────
        # High unique destination ports per source IP = port scan signal
        ports_per_src = df.groupby("src_ip")["dst_port"].nunique()
        max_ports_per_src   = float(ports_per_src.max())
        mean_ports_per_src  = float(ports_per_src.mean())

        # ── SYN Flood Heuristic ────────────────────────────────────────────────
        syn_packets = df[df["flags"].str.contains("S", na=False) &
                         ~df["flags"].str.contains("A", na=False)]
        syn_ratio = len(syn_packets) / total_packets

        # ── Traffic Entropy (src IP diversity) ────────────────────────────────
        src_ip_counts = df["src_ip"].value_counts(normalize=True)
        entropy = float(-np.sum(src_ip_counts * np.log2(src_ip_counts + 1e-9)))

        return {
            # Meta
            "window_end":           datetime.utcnow().isoformat(),
            "total_packets":        total_packets,
            # Volume
            "unique_src_ips":       unique_src_ips,
            "unique_dst_ips":       unique_dst_ips,
            "unique_dst_ports":     unique_dst_ports,
            "packet_rate":          round(packet_rate, 4),
            # Protocol
            "tcp_count":            tcp_count,
            "udp_count":            udp_count,
            "icmp_count":           icmp_count,
            "tcp_ratio":            round(tcp_ratio, 4),
            "udp_ratio":            round(udp_ratio, 4),
            # Payload
            "payload_mean":         round(payload_mean, 4),
            "payload_std":          round(payload_std, 4),
            "payload_max":          payload_max,
            "payload_min":          payload_min,
            "payload_median":       payload_median,
            # Heuristics
            "syn_ratio":            round(syn_ratio, 4),
            "max_ports_per_src":    max_ports_per_src,
            "mean_ports_per_src":   round(mean_ports_per_src, 4),
            "src_ip_entropy":       round(entropy, 4),
        }

    # ── Worker Loop ────────────────────────────────────────────────────────────
    def _run(self) -> None:
        """Background thread: drain queue → evict old → compute → publish."""
        logger.info("✅ Feature extractor thread started.")
        while self._running:
            with self._lock:
                self._drain_queue()
                self._evict_old_packets()
                features = self._compute_features()

            if features:
                try:
                    self.output_queue.put_nowait(features)
                    self._vectors_produced += 1
                    logger.debug(
                        f"Feature vector #{self._vectors_produced} produced "
                        f"— {features['total_packets']} packets in window."
                    )
                except queue.Full:
                    logger.warning("Output queue full — feature vector dropped.")

            time.sleep(self.poll_interval)

        logger.info("🛑 Feature extractor thread stopped.")

    # ── Start / Stop ───────────────────────────────────────────────────────────
    def start(self) -> None:
        if self._running:
            logger.warning("Feature extractor already running.")
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="FeatureExtractor")
        self._thread.start()
        logger.info("Feature extractor started.")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info(f"Feature extractor stopped. Vectors produced: {self._vectors_produced}")

    # ── Status ─────────────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        return {
            "running":          self._running,
            "buffer_size":      len(self._buffer),
            "vectors_produced": self._vectors_produced,
        }

