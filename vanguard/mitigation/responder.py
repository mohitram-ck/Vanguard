"""
Vanguard NIDS — Mitigation Engine Module
Automated threat response: blocks malicious IPs via firewall rules
and logs all events securely with tamper-evident audit trails.
"""

import hashlib
import json
import logging
import os
import platform
import queue
import subprocess
import threading
import time
from datetime import datetime
from typing import Optional

import colorlog

from vanguard.ai_engine.detector import DetectionResult

# ── Logging Setup ──────────────────────────────────────────────────────────────
LOG_DIR  = "logs"
LOG_FILE = os.path.join(LOG_DIR, "vanguard_events.log")
os.makedirs(LOG_DIR, exist_ok=True)

# Console handler with colors
_console_handler = colorlog.StreamHandler()
_console_handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    log_colors={
        "DEBUG":    "cyan",
        "INFO":     "green",
        "WARNING":  "yellow",
        "ERROR":    "red",
        "CRITICAL": "bold_red",
    }
))

# File handler — plain text for audit trail
_file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
))

logger = logging.getLogger("vanguard.mitigation")
logger.setLevel(logging.DEBUG)
logger.addHandler(_console_handler)
logger.addHandler(_file_handler)


# ── OS Detection ───────────────────────────────────────────────────────────────
IS_LINUX   = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"
IS_MAC     = platform.system() == "Darwin"


# ── Secure Audit Logger ────────────────────────────────────────────────────────
class SecureAuditLogger:
    """
    Writes tamper-evident JSON audit logs.
    Each log entry contains a SHA-256 hash of the previous entry,
    forming a hash chain — any modification breaks the chain.
    """

    AUDIT_FILE = os.path.join(LOG_DIR, "audit_chain.jsonl")

    def __init__(self):
        self._lock = threading.Lock()
        self._last_hash = "GENESIS"  # Chain anchor

        # If file exists, read the last hash to continue the chain
        if os.path.exists(self.AUDIT_FILE):
            with open(self.AUDIT_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if lines:
                    try:
                        last = json.loads(lines[-1])
                        self._last_hash = last.get("entry_hash", "GENESIS")
                    except json.JSONDecodeError:
                        pass

    def _hash_entry(self, entry: dict) -> str:
        """SHA-256 hash of the JSON entry + previous hash."""
        content = json.dumps(entry, sort_keys=True) + self._last_hash
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def log(self, event_type: str, data: dict) -> None:
        """Write a tamper-evident entry to the audit chain."""
        with self._lock:
            entry = {
                "timestamp":  datetime.utcnow().isoformat(),
                "event_type": event_type,
                "data":       data,
                "prev_hash":  self._last_hash,
            }
            entry["entry_hash"] = self._hash_entry(entry)
            self._last_hash = entry["entry_hash"]

            with open(self.AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")


# ── Firewall Interface ─────────────────────────────────────────────────────────
class FirewallManager:
    """
    Cross-platform firewall abstraction.
    - Linux  → iptables
    - macOS  → pfctl
    - Windows → netsh advfirewall
    """

    def __init__(self, dry_run: bool = False):
        """
        Args:
            dry_run: If True, log commands but don't execute them.
                     Use this during development/testing on Windows.
        """
        self.dry_run    = dry_run
        self._blocked:  set[str] = set()
        self._lock      = threading.Lock()

    def _run_command(self, cmd: list[str]) -> tuple[bool, str]:
        """Execute a shell command safely, return (success, output)."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute: {' '.join(cmd)}")
            return True, "dry_run"

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                logger.error(f"Command failed: {result.stderr.strip()}")
                return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(cmd)}")
            return False, "timeout"
        except FileNotFoundError:
            logger.error(f"Command not found: {cmd[0]}")
            return False, "not_found"

    def block_ip(self, ip: str) -> bool:
        """Block an IP address using the appropriate OS firewall."""
        with self._lock:
            if ip in self._blocked:
                logger.info(f"IP {ip} already blocked — skipping.")
                return True

            success = False

            if IS_LINUX:
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                success, _ = self._run_command(cmd)

            elif IS_MAC:
                # macOS uses pfctl — add rule to /etc/pf.conf
                cmd = ["pfctl", "-t", "vanguard_blocklist", "-T", "add", ip]
                success, _ = self._run_command(cmd)

            elif IS_WINDOWS:
                rule_name = f"Vanguard_Block_{ip.replace('.', '_')}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}"
                ]
                success, _ = self._run_command(cmd)

            else:
                logger.error(f"Unsupported OS: {platform.system()}")
                return False

            if success:
                self._blocked.add(ip)
                logger.critical(f"🔒 BLOCKED IP: {ip}")

            return success

    def unblock_ip(self, ip: str) -> bool:
        """Remove a block rule for an IP address."""
        with self._lock:
            if ip not in self._blocked:
                logger.warning(f"IP {ip} is not currently blocked.")
                return False

            success = False

            if IS_LINUX:
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                success, _ = self._run_command(cmd)

            elif IS_MAC:
                cmd = ["pfctl", "-t", "vanguard_blocklist", "-T", "delete", ip]
                success, _ = self._run_command(cmd)

            elif IS_WINDOWS:
                rule_name = f"Vanguard_Block_{ip.replace('.', '_')}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ]
                success, _ = self._run_command(cmd)

            if success:
                self._blocked.discard(ip)
                logger.info(f"🔓 UNBLOCKED IP: {ip}")

            return success

    def get_blocked_ips(self) -> set[str]:
        return set(self._blocked)


# ── Mitigation Engine ──────────────────────────────────────────────────────────
class MitigationEngine:
    """
    Consumes DetectionResults from the AI Engine.
    For MALICIOUS results: extracts source IPs, blocks them via
    FirewallManager, and logs every action to the secure audit chain.
    """

    def __init__(
        self,
        result_queue: queue.Queue,
        dry_run: bool = False,
        poll_interval: float = 0.5,
        whitelist: Optional[list[str]] = None,
    ):
        """
        Args:
            result_queue:  Input queue from AnomalyDetector.
            dry_run:       If True, simulate firewall commands.
            poll_interval: How often to check queue (seconds).
            whitelist:     IPs that should NEVER be blocked (e.g. your own machine).
        """
        self.result_queue   = result_queue
        self.poll_interval  = poll_interval
        self.whitelist      = set(whitelist or ["127.0.0.1", "::1"])

        self._firewall      = FirewallManager(dry_run=dry_run)
        self._audit         = SecureAuditLogger()
        self._running       = False
        self._thread:       Optional[threading.Thread] = None

        self._total_processed   = 0
        self._total_blocked     = 0
        self._total_benign      = 0

    # ── Response Logic ─────────────────────────────────────────────────────────
    def _respond(self, result: DetectionResult) -> None:
        """Handle a single DetectionResult."""
        self._total_processed += 1

        if not result.is_malicious():
            self._total_benign += 1
            self._audit.log("BENIGN", {
                "score":           result.score,
                "total_packets":   result.features.get("total_packets"),
            })
            return

        # ── Malicious Traffic Detected ─────────────────────────────────────────
        features    = result.features
        score       = result.score

        # Log the threat event immediately
        logger.critical(
            f"🚨 THREAT RESPONSE TRIGGERED | "
            f"Score: {score:.4f} | "
            f"Packets: {features.get('total_packets')} | "
            f"SYN Ratio: {features.get('syn_ratio')} | "
            f"Unique Ports: {features.get('unique_dst_ports')}"
        )

        # Audit the detection
        self._audit.log("MALICIOUS_DETECTED", {
            "score":    score,
            "features": features,
        })

        # Note: In a real deployment, you would extract attacker IPs
        # from the packet-level data. Here we simulate with a placeholder
        # since our feature vectors are window-level aggregates.
        # The PacketRecord-level data would feed IP extraction directly.
        attacker_ip = features.get("top_src_ip", None)

        if attacker_ip and attacker_ip not in self.whitelist:
            blocked = self._firewall.block_ip(attacker_ip)
            if blocked:
                self._total_blocked += 1
                self._audit.log("IP_BLOCKED", {
                    "ip":    attacker_ip,
                    "score": score,
                })
        else:
            logger.warning(
                "No specific attacker IP available at window level — "
                "logged threat without IP block. "
                "Connect packet-level stream for IP-level blocking."
            )
            self._audit.log("THREAT_LOGGED_NO_BLOCK", {
                "reason": "IP not available at feature-window level",
                "score":  score,
            })

    # ── Background Worker ──────────────────────────────────────────────────────
    def _run(self) -> None:
        logger.info("✅ Mitigation engine thread started.")
        while self._running:
            try:
                result = self.result_queue.get(timeout=self.poll_interval)
                self._respond(result)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Mitigation error: {e}", exc_info=True)

        logger.info("🛑 Mitigation engine stopped.")

    # ── Start / Stop ───────────────────────────────────────────────────────────
    def start(self) -> None:
        if self._running:
            logger.warning("Mitigation engine already running.")
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="MitigationEngine"
        )
        self._thread.start()
        logger.info("✅ Mitigation engine started.")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info(
            f"🛑 Mitigation engine stopped. "
            f"Processed: {self._total_processed} | "
            f"Benign: {self._total_benign} | "
            f"Blocked: {self._total_blocked}"
        )

    # ── Status ─────────────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        return {
            "running":          self._running,
            "total_processed":  self._total_processed,
            "total_benign":     self._total_benign,
            "total_blocked":    self._total_blocked,
            "blocked_ips":      list(self._firewall.get_blocked_ips()),
        }
