"""
IDS Package
===========

This package implements a modular Intrusion Detection System (IDS)
following a clean, layered architecture.

Modules included:
-----------------
- capture/
    Responsible for packet acquisition using Scapy, Pyshark,
    raw sockets, and live listeners.

- preprocessing/
    Handles packet parsing, transformation into structured
    formats (DataFrame), and feature extraction.

- detection/
    Contains signature-based and rule-based intrusion detectors
    (SYN flood, ARP spoofing, port scans, etc.).

- utils/
    General utilities such as configuration loading, logging,
    and helper functions.

- api/ (optional)
    Web API (Flask/Django) to expose real-time alerts or packet info.

This file initializes the IDS package and exposes the main subpackages.
"""

# Exposing subpackages for easier imports
from ids import capture
  