"""Ingestion API for forwarding captured packets to the detection engine.

Expose a simple function `ingest_packet(packet)` that enqueues packets for
analysis by the detection engine running in a background worker thread.

This module is intentionally lightweight and resilient: detection errors are
caught and logged but do not propagate to the caller.
"""
from __future__ import annotations

import threading
import queue
import time
import logging
import json
from typing import Any, Dict

from ids.detection.engine import DetectionEngine
from ids.utils import config as cfg
from ids.preprocessing.packet_parser import normalize_packet

logger = logging.getLogger(__name__)

# Single global engine instance used by ingest()
_engine: DetectionEngine | None = None
_queue: queue.Queue | None = None
_worker_thread: threading.Thread | None = None
_stop_event = threading.Event()


def _ensure_started() -> None:
    global _engine, _queue, _worker_thread
    if _engine is None:
        _engine = DetectionEngine()
    if _queue is None:
        # bounded queue to avoid unbounded memory growth under load
        maxsize = int(cfg.get('queue_maxsize') or 5000)
        _queue = queue.Queue(maxsize=maxsize)
    if _worker_thread is None or not _worker_thread.is_alive():
        _stop_event.clear()
        _worker_thread = threading.Thread(target=_worker, daemon=True)
        _worker_thread.start()


def _worker() -> None:
    assert _queue is not None
    while not _stop_event.is_set():
        try:
            pkt = _queue.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            findings = _engine.analyze(pkt)
            for f in findings:
                # suppress non-actionable/verbose findings like NULL scans
                try:
                    ftype = f.get('type') if isinstance(f, dict) else None
                except Exception:
                    ftype = None
                if ftype == 'null_scan':
                    # skip emitting or logging null scan findings to avoid noise
                    continue
                logger.info('Detection finding: %s', f)
                # emit findings as JSON lines so external monitors (GUI) can pick them up
                try:
                    out = {'_type': 'detection', 'timestamp': time.time(), 'finding': f}
                    print(json.dumps(out, default=str), flush=True)
                except Exception:
                    logger.exception('Failed to print detection finding')
        except Exception as e:
            logger.exception('Error running detection on packet: %s', e)
        finally:
            _queue.task_done()


def ingest_packet(packet: Dict[str, Any]) -> None:
    """Accept a packet dict and enqueue it for detection analysis.

    This call is non-blocking and returns quickly. Any exceptions in the
    detection pipeline are caught and logged; they do not propagate to the
    caller.
    """
    try:
        _ensure_started()
        assert _queue is not None
        # Normalize packet before handing off to detectors
        try:
            pkt = normalize_packet(packet)
        except Exception as e:
            logger.warning(f"Failed to normalize packet: {e}")
            pkt = packet

        try:
            _queue.put(pkt, timeout=0.2)
        except queue.Full:
            # Drop packet if queue is full; do not block caller
            logger.warning('Ingest queue full; dropping packet')
    except Exception as e:
        logger.exception(f"Failed to enqueue packet for detection: {e}")


def stop() -> None:
    """Stop the worker thread and wait for shutdown.

    Useful for tests and clean shutdowns.
    """
    _stop_event.set()
    if _queue is not None:
        _queue.join()


def reload_engine() -> None:
    """Force recreation of the detection engine using current configuration.

    This will replace the global engine instance. The worker thread will
    pick up the new engine on the next packet processed.
    """
    global _engine
    try:
        _engine = None
        logger.info('Detection engine will be recreated on next ingest')
    except Exception:
        logger.exception('Failed to reload detection engine')
