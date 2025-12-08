"""Rule management module for IDS.

Handles all rule CRUD operations and rule file persistence.
"""

import json
import os
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

RULES_FILE = "rules.json"

# Available field options for rule creation
AVAILABLE_FIELDS = ["Source IP", "Destination IP", "Protocol", "Port", "Length", "TTL"]

# Available operators for rule creation
AVAILABLE_OPERATORS = ["equals", "not equals", "contains", "greater than", "less than", "cidr"]

# Available actions for rules
AVAILABLE_ACTIONS = ["Alert", "Drop Packet", "Log"]


def load_rules_from_file() -> List[Dict[str, Any]]:
    """Load rules from the configuration file.
    
    Returns:
        List of rule dictionaries
    """
    if not os.path.exists(RULES_FILE):
        logger.info("Rules file not found, returning empty rules list")
        return []
    
    try:
        with open(RULES_FILE, "r") as file:
            rules = json.load(file)
            logger.info("Loaded %d rules from %s", len(rules), RULES_FILE)
            return rules
    except json.JSONDecodeError as e:
        logger.error("Failed to parse rules.json: %s", e)
        return []
    except Exception as e:
        logger.error("Failed to load rules: %s", e)
        return []


def save_rules_to_file(rules: List[Dict[str, Any]]) -> bool:
    """Save rules to the configuration file.
    
    Args:
        rules: List of rule dictionaries
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(RULES_FILE, "w") as file:
            json.dump(rules, file, indent=4)
        logger.info("Saved %d rules to %s", len(rules), RULES_FILE)
        return True
    except Exception as e:
        logger.error("Failed to save rules: %s", e)
        return False


def add_rule(rule: Dict[str, Any]) -> bool:
    """Add a new rule to the file.
    
    Args:
        rule: Rule dictionary with keys: name, field, operator, value, action
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Validate rule
    required_fields = ["name", "field", "operator", "value", "action"]
    if not all(key in rule for key in required_fields):
        logger.error("Rule missing required fields: %s", rule)
        return False
    
    rules = load_rules_from_file()
    rules.append(rule)
    return save_rules_to_file(rules)


def update_rule(rule_index: int, rule: Dict[str, Any]) -> bool:
    """Update an existing rule.
    
    Args:
        rule_index: Index of the rule to update
        rule: Updated rule dictionary
        
    Returns:
        bool: True if successful, False otherwise
    """
    rules = load_rules_from_file()
    
    if rule_index < 0 or rule_index >= len(rules):
        logger.error("Invalid rule index: %d", rule_index)
        return False
    
    rules[rule_index] = rule
    return save_rules_to_file(rules)


def delete_rule(rule_index: int) -> bool:
    """Delete a rule.
    
    Args:
        rule_index: Index of the rule to delete
        
    Returns:
        bool: True if successful, False otherwise
    """
    rules = load_rules_from_file()
    
    if rule_index < 0 or rule_index >= len(rules):
        logger.error("Invalid rule index: %d", rule_index)
        return False
    
    deleted_rule = rules.pop(rule_index)
    logger.info("Deleted rule: %s", deleted_rule)
    return save_rules_to_file(rules)


def get_rule_by_index(rule_index: int) -> Dict[str, Any] | None:
    """Get a rule by its index.
    
    Args:
        rule_index: Index of the rule
        
    Returns:
        Rule dictionary or None if not found
    """
    rules = load_rules_from_file()
    
    if rule_index < 0 or rule_index >= len(rules):
        return None
    
    return rules[rule_index]


def validate_rule(rule: Dict[str, Any]) -> tuple[bool, str]:
    """Validate a rule before saving.
    
    Args:
        rule: Rule dictionary to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    required_fields = ["name", "field", "operator", "value", "action"]
    
    for field in required_fields:
        if field not in rule or not rule[field]:
            return False, f"Missing required field: {field}"
    
    if not isinstance(rule["name"], str) or not rule["name"].strip():
        return False, "Rule name must be a non-empty string"
    
    if rule["action"] not in AVAILABLE_ACTIONS:
        return False, f"Invalid action. Must be one of: {', '.join(AVAILABLE_ACTIONS)}"
    
    return True, ""
