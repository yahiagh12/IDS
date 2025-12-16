"""Small helpers shared by capture backends.

Provide a single place to build the canonical packet dictionary so backends
produce consistent fields with minimal duplicated code.
"""
from datetime import datetime
from typing import Any, Dict, Optional


def make_packet_dict(src: str, dst: str, proto: str, length: int, summary: str = "", 
                     src_port: Optional[int] = None, dst_port: Optional[int] = None, 
                     raw: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Create a canonical packet dictionary.
    
    Args:
        src: Source IP
        dst: Destination IP
        proto: Protocol (TCP, UDP, ICMP, ARP, etc.)
        length: Packet length in bytes
        summary: Packet summary string
        src_port: Source port (optional, for TCP/UDP)
        dst_port: Destination port (optional, for TCP/UDP)
        raw: Raw packet data from capture backend
        
    Returns:
        Dictionary with standardized packet fields
    """
    packet = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "protocol": proto,
        "length": length,
        "summary": summary,
        "_raw": raw or {},
    }
    
    # Add ports if available
    if src_port is not None:
        packet["src_port"] = src_port
    if dst_port is not None:
        packet["dst_port"] = dst_port
    
    # For convenience, also add 'port' field (usually destination port)
    if dst_port is not None:
        packet["port"] = dst_port
    
    return packet

