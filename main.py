"""
Vanguard NIDS — Main Entry Point
Wires all 4 modules together into a single running system.

Usage:
    python main.py --mode train    # Capture baseline traffic and train the model
    python main.py --mode run      # Run live detection with trained model
    python main.py --mode demo     # Run with simulated data (no network needed)
"""

import argparse
import logging
import queue
import signal
import sys
import time
import random
from datetime import datetime

from vanguard.ingestion.packet_capture import PacketCaptureEngine, PacketRecord
from vanguard.features.feature_extractor import FeatureExtractor
from vanguard.ai_engine.detector import AnomalyDetector
from vanguard.mitigation.responder import MitigationEngine

# ── Root Logger Setup ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("vanguard.main")

# ── Shared Queues (the arteries connecting all modules) ────────────────────────
PACKET_QUEUE  = queue.Queue(maxsize=10000)   # Ingestion → Feature Extractor
FEATURE_QUEUE = queue.Queue(maxsize=1000)    # Feature Extractor → AI Engine
RESULT_QUEUE  = queue.Queue(maxsize=1000)    # AI Engine → Mitigation Engine


# ── Graceful Shutdown Handler ──────────────────────────────────────────────────
class VanguardSystem:
    """Orchestrates the full Vanguard pipeline."""

    def __init__(self, args):
        self.args       = args
        self._running   = False

        # ── Instantiate all modules ────────────────────────────────────────────
        self.capture = PacketCaptureEngine(
            interface=args.interface,
            queue_maxsize=10000
        )

        self.extractor = FeatureExtractor(
            packet_queue=PACKET_QUEUE,
            output_queue=FEATURE_QUEUE,
            window_seconds=args.window,
            poll_interval=1.0
        )

        self.detector = AnomalyDetector(
            feature_queue=FEATURE_QUEUE,
            result_queue=RESULT_QUEUE,
            contamination=0.05,
            poll_interval=0.5,
            on_alert=self._on_alert   # Immediate callback on threat
        )

        self.mitigator = MitigationEngine(
            result_queue=RESULT_QUEUE,
            dry_run=args.dry_run,
            whitelist=["127.0.0.1", "::1"]
        )

    # ── Alert Callback ─────────────────────────────────────────────────────────
    def _on_alert(self, result) -> None:
        """Fired immediately when AI Engine detects malicious traffic."""
        print("\n" + "="*60)
        print(f"  🚨 VANGUARD ALERT — {datetime.utcnow().isoformat()}")
        print(f"  Score     : {result.score:.6f}")
        print(f"  Packets   : {result.features.get('total_packets')}")
        print(f"  SYN Ratio : {result.features.get('syn_ratio')}")
        print(f"  Uniq Ports: {result.features.get('unique_dst_ports')}")
        print(f"  Entropy   : {result.features.get('src_ip_entropy')}")
        print("="*60 + "\n")

    # ── Training Mode ──────────────────────────────────────────────────────────
    def run_training(self) -> None:
        """
        Capture live traffic for N seconds to build a baseline,
        then train and save the Isolation Forest model.
        """
        duration = self.args.train_duration
        logger.info(f"🎓 TRAINING MODE — Capturing {duration}s of baseline traffic...")
        logger.info("Make sure this is NORMAL traffic — no attacks during training!")

        # Start capture + extraction only
        self.capture.start()

        # Point extractor queue directly — collect vectors into a list
        training_vectors = []
        temp_out = queue.Queue()

        trainer_extractor = FeatureExtractor(
            packet_queue=self.capture.packet_queue,
            output_queue=temp_out,
            window_seconds=self.args.window,
            poll_interval=1.0
        )
        trainer_extractor.start()

        # Collect feature vectors for the training duration
        end_time = time.time() + duration
        while time.time() < end_time:
            remaining = int(end_time - time.time())
            print(f"\r  ⏳ Collecting baseline... {remaining}s remaining", end="", flush=True)
            try:
                vec = temp_out.get(timeout=1.0)
                training_vectors.append(vec)
            except queue.Empty:
                continue

        print()  # newline after countdown
        trainer_extractor.stop()
        self.capture.stop()

        if not training_vectors:
            logger.error("No feature vectors collected. Is there network traffic?")
            logger.info("💡 Try running in --mode demo to test with simulated data.")
            sys.exit(1)

        logger.info(f"✅ Collected {len(training_vectors)} feature vectors. Training model...")
        self.detector.train(training_vectors)
        logger.info("🎓 Training complete! Now run: python main.py --mode run")

    # ── Demo Mode (Simulated Data) ─────────────────────────────────────────────
    def run_demo(self) -> None:
        """
        Simulates packet data without requiring real network capture.
        Perfect for testing on Windows or in restricted environments.
        """
        logger.info("🧪 DEMO MODE — Generating simulated traffic data...")

        import numpy as np

        # Generate synthetic normal traffic
        normal_vectors = []
        for _ in range(100):
            normal_vectors.append({
                "total_packets":      random.randint(50, 200),
                "unique_src_ips":     random.randint(1, 10),
                "unique_dst_ips":     random.randint(1, 10),
                "unique_dst_ports":   random.randint(1, 5),
                "packet_rate":        random.uniform(5, 30),
                "tcp_count":          random.randint(30, 150),
                "udp_count":          random.randint(5, 30),
                "icmp_count":         random.randint(0, 5),
                "tcp_ratio":          random.uniform(0.6, 0.85),
                "udp_ratio":          random.uniform(0.1, 0.3),
                "payload_mean":       random.uniform(200, 800),
                "payload_std":        random.uniform(50, 200),
                "payload_max":        random.uniform(800, 1500),
                "payload_min":        random.uniform(20, 100),
                "payload_median":     random.uniform(200, 700),
                "syn_ratio":          random.uniform(0.01, 0.05),
                "max_ports_per_src":  random.uniform(1, 5),
                "mean_ports_per_src": random.uniform(1, 3),
                "src_ip_entropy":     random.uniform(0.5, 2.0),
            })

        # Train on normal traffic
        logger.info("Training model on simulated normal traffic...")
        self.detector.train(normal_vectors)

        # Start mitigation engine
        self.mitigator.start()

        # Now feed a mix of normal + attack vectors
        logger.info("Running detection on simulated live traffic (Ctrl+C to stop)...")
        self._running = True
        vector_count = 0

        try:
            while self._running:
                is_attack = random.random() < 0.2  # 20% chance of attack

                if is_attack:
                    # Simulate a SYN flood / port scan
                    vec = {
                        "total_packets":      random.randint(5000, 20000),
                        "unique_src_ips":     random.randint(1, 3),
                        "unique_dst_ips":     random.randint(1, 2),
                        "unique_dst_ports":   random.randint(500, 1000),
                        "packet_rate":        random.uniform(500, 2000),
                        "tcp_count":          random.randint(4000, 18000),
                        "udp_count":          random.randint(0, 100),
                        "icmp_count":         random.randint(0, 50),
                        "tcp_ratio":          random.uniform(0.95, 1.0),
                        "udp_ratio":          random.uniform(0.0, 0.02),
                        "payload_mean":       random.uniform(40, 80),
                        "payload_std":        random.uniform(5, 20),
                        "payload_max":        random.uniform(100, 200),
                        "payload_min":        0,
                        "payload_median":     random.uniform(40, 80),
                        "syn_ratio":          random.uniform(0.85, 1.0),
                        "max_ports_per_src":  random.uniform(400, 1000),
                        "mean_ports_per_src": random.uniform(400, 900),
                        "src_ip_entropy":     random.uniform(0.0, 0.3),
                    }
                else:
                    # Normal traffic
                    vec = normal_vectors[vector_count % len(normal_vectors)]

                result = self.detector.predict(vec)
                RESULT_QUEUE.put_nowait(result)
                vector_count += 1

                time.sleep(1.5)

        except KeyboardInterrupt:
            logger.info("Demo interrupted by user.")
        finally:
            self.mitigator.stop()
            self._print_stats()

    # ── Live Run Mode ──────────────────────────────────────────────────────────
    def run_live(self) -> None:
        """Full live pipeline — requires trained model and Npcap/root."""
        if not self.detector.load():
            logger.error("No trained model found. Run --mode train first.")
            sys.exit(1)

        logger.info("🚀 Starting Vanguard live detection pipeline...")

        # Register Ctrl+C shutdown
        signal.signal(signal.SIGINT,  self._shutdown_handler)
        signal.signal(signal.SIGTERM, self._shutdown_handler)

        # Start all modules in order
        self.capture.start()
        self.extractor.start()
        self.detector.start()
        self.mitigator.start()

        self._running = True
        logger.info("✅ All modules running. Press Ctrl+C to stop.")

        # Keep main thread alive + print periodic stats
        try:
            while self._running:
                time.sleep(10)
                self._print_stats()
        except KeyboardInterrupt:
            self._shutdown()

    # ── Shutdown ───────────────────────────────────────────────────────────────
    def _shutdown_handler(self, sig, frame):
        logger.info("Shutdown signal received...")
        self._running = False
        self._shutdown()

    def _shutdown(self):
        logger.info("🛑 Shutting down Vanguard...")
        self.capture.stop()
        self.extractor.stop()
        self.detector.stop()
        self.mitigator.stop()
        self._print_stats()
        sys.exit(0)

    # ── Stats Dashboard ────────────────────────────────────────────────────────
    def _print_stats(self):
        print("\n" + "─"*50)
        print("  📊 VANGUARD SYSTEM STATUS")
        print("─"*50)
        for name, module in [
            ("Ingestion",   self.capture),
            ("Extractor",   self.extractor),
            ("AI Engine",   self.detector),
            ("Mitigator",   self.mitigator),
        ]:
            stats = module.get_stats()
            print(f"  {name:12} → {stats}")
        print("─"*50 + "\n")


# ── CLI Argument Parser ────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="Vanguard — AI-Powered Network Intrusion Detection System"
    )
    parser.add_argument(
        "--mode",
        choices=["train", "run", "demo"],
        default="demo",
        help="train: capture baseline | run: live detection | demo: simulated data"
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface to sniff (e.g. 'Wi-Fi', 'eth0'). Default: auto"
    )
    parser.add_argument(
        "--window",
        type=int,
        default=10,
        help="Rolling time window in seconds for feature extraction (default: 10)"
    )
    parser.add_argument(
        "--train-duration",
        type=int,
        default=60,
        help="Seconds of baseline traffic to capture during training (default: 60)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate firewall commands without executing them"
    )
    return parser.parse_args()


# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════╗
║   🛡️  VANGUARD — AI-Powered NIDS  🛡️    ║
║   Network Intrusion Detection System     ║
╚══════════════════════════════════════════╝
    """)

    args = parse_args()
    system = VanguardSystem(args)

    if args.mode == "train":
        system.run_training()
    elif args.mode == "run":
        system.run_live()
    elif args.mode == "demo":
        system.run_demo()


