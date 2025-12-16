"""Central logger configuration for IDS modules."""
import logging


def configure(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
    )


def get_logger(name):
    return logging.getLogger(name)
