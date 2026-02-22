"""
Vanguard NIDS — Data Ingestion Module
Asynchronous packet capture engine using Scapy.
"""

import logging
import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP

# ── Logging Setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("vanguard.ingestion")


# ── Packet Data Model ──────────────────────────────────────────────────────────
@dataclass
class PacketRecord:
    """Structured representation of a captured network packet."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    payload_size: int
    flags: Optional[str] = field(default=None)
    raw_summary: str = field(default="")


# ── Packet Capture Engine ──────────────────────────────────────────────────────
class PacketCaptureEngine:
    """
    Asynchronously sniffs network packets and pushes structured
    PacketRecord objects into a thread-safe queue for downstream processing.
    """

    def __init__(self, interface: Optional[str] = None, queue_maxsize: int = 10000):
        """
        Args:
            interface:    Network interface to sniff on (e.g., 'eth0', 'Wi-Fi').
                          None lets Scapy auto-select the default interface.
            queue_maxsize: Max packets held in buffer before dropping.
        """
        self.interface = interface
        self.packet_queue: queue.Queue[PacketRecord] = queue.Queue(maxsize=queue_maxsize)
        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._running = False
        self._captured = 0
        self._dropped = 0

    # ── Internal Packet Parser ─────────────────────────────────────────────────
    def _parse_packet(self, pkt) -> Optional[PacketRecord]:
        """Extract fields from a raw Scapy packet into a PacketRecord."""
        if not pkt.haslayer(IP):
            return None  # Ignore non-IP traffic (ARP, etc.)

        ip_layer = pkt[IP]
        protocol = "OTHER"
        src_port = dst_port = None
        flags = None

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            protocol = "TCP"
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = str(tcp.flags)

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            protocol = "UDP"
            src_port = udp.sport
            dst_port = udp.dport

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        payload_size = len(pkt.payload)

        return PacketRecord(
            timestamp=datetime.utcnow(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            payload_size=payload_size,
            flags=flags,
            raw_summary=pkt.summary()
        )

    # ── Queue Handler ──────────────────────────────────────────────────────────
    def _handle_packet(self, pkt) -> None:
        """Callback invoked by Scapy for every sniffed packet."""
        record = self._parse_packet(pkt)
        if record is None:
            return

        try:
            self.packet_queue.put_nowait(record)
            self._captured += 1
        except queue.Full:
            self._dropped += 1
            logger.warning(
                f"Packet queue full — dropped packet from {record.src_ip}. "
                f"Total dropped: {self._dropped}"
            )

    # ── Start / Stop ───────────────────────────────────────────────────────────
    def start(self) -> None:
        """Start the async packet sniffer."""
        with self._lock:
            if self._running:
                logger.warning("Capture engine is already running.")
                return

            logger.info(
                f"Starting packet capture on interface: "
                f"{'auto' if not self.interface else self.interface}"
            )

            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._handle_packet,
                store=False  # Don't store packets in memory — we handle them
            )
            self._sniffer.start()
            self._running = True
            logger.info("✅ Packet capture engine started.")

    def stop(self) -> None:
        """Gracefully stop the async packet sniffer."""
        with self._lock:
            if not self._running or self._sniffer is None:
                logger.warning("Capture engine is not running.")
                return

            self._sniffer.stop()
            self._running = False
            logger.info(
                f"🛑 Capture engine stopped. "
                f"Captured: {self._captured} | Dropped: {self._dropped}"
            )

    # ── Status ─────────────────────────────────────────────────────────────────
    @property
    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict:
        return {
            "running": self._running,
            "captured": self._captured,
            "dropped": self._dropped,
            "queue_size": self.packet_queue.qsize()
        }

