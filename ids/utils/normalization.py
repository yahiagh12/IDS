"""Normalization utilities for consistent field and operator handling.

This module provides functions to normalize field names and operators
across the IDS application for consistent rule matching.
"""

import ipaddress


def normalize_field_name(field):
    """Normalize field names for consistent comparison.
    
    Args:
        field (str): Original field name
        
    Returns:
        str: Normalized field name
    """
    if not field:
        return ""
    
    # Convert to lowercase for case-insensitive comparison
    normalized = field.lower().strip()
    
    # Map common field name variations
    field_mappings = {
        "src": "src_ip",
        "source": "src_ip",
        "source_ip": "src_ip",
        "destination": "dst_ip",
        "dest": "dst_ip",
        "destination_ip": "dst_ip",
        "protocol": "protocol",
        "proto": "protocol",
        "port": "dst_port",
        "dst_port": "dst_port",
        "destination_port": "dst_port",
        "src_port": "src_port",
        "source_port": "src_port",
        "length": "length",
        "packet_length": "length",
        "size": "length",
        "ttl": "ttl",
        "flags": "flags",
    }
    
    return field_mappings.get(normalized, normalized)


def normalize_operator(operator):
    """Normalize operator names for consistent comparison.
    
    Args:
        operator (str): Original operator name
        
    Returns:
        str: Normalized operator name
    """
    if not operator:
        return ""
    
    normalized = operator.lower().strip()
    
    # Map operator variations
    operator_mappings = {
        "=": "equals",
        "==": "equals",
        "!=": "not_equals",
        "not_equal": "not_equals",
        ">": "greater_than",
        "gt": "greater_than",
        "<": "less_than",
        "lt": "less_than",
        ">=": "greater_or_equal",
        "<=": "less_or_equal",
        "contains": "contains",
        "in": "in",
        "cidr": "cidr",
        "in_cidr": "cidr",
    }
    
    return operator_mappings.get(normalized, normalized)


def is_ip_in_cidr(ip_str, cidr_str):
    """Check if an IP address is within a CIDR block.
    
    Args:
        ip_str (str): IP address to check
        cidr_str (str): CIDR block (e.g., "192.168.1.0/24")
        
    Returns:
        bool: True if IP is in CIDR block, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr_str, strict=False)
        return ip in network
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False


def normalize_value(value, operator):
    """Normalize value based on operator type.
    
    Args:
        value: Value to normalize
        operator (str): Operator type
        
    Returns:
        Normalized value appropriate for the operator
    """
    operator = normalize_operator(operator).lower()
    
    if operator in ["greater_than", "less_than", "greater_or_equal", "less_or_equal"]:
        try:
            return int(value)
        except (ValueError, TypeError):
            return value
    
    return str(value).lower() if value else ""
