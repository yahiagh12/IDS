"""Small internal API exposing an endpoint to ingest packets.

This optional Flask app can be enabled to receive packets over HTTP and
forward them to the same ingest pipeline used by the runner.
"""
try:
    from flask import Flask, request, jsonify
except Exception:  # pragma: no cover - Flask may not be installed
    Flask = None

from ids.api import ingest
import json
import os

RULES_FILE = "rules.json"


def create_app():
    if Flask is None:
        raise RuntimeError('Flask is not installed')
    app = Flask(__name__)

    @app.route('/ingest', methods=['POST'])
    def ingest_route():
        pkt = request.get_json()
        if not pkt:
            return jsonify({'error': 'no JSON payload'}), 400
        try:
            ingest.ingest_packet(pkt)
            return jsonify({'status': 'ok'}), 202
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return app

def load_rules():
    """Load rules from the configuration file."""
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE, "r") as file:
        return json.load(file)

def save_rules(rules):
    """Save rules to the configuration file."""
    with open(RULES_FILE, "w") as file:
        json.dump(rules, file, indent=4)

def apply_rules_to_engine(rules):
    """Apply rules to the detection engine."""
    from ids.detection.engine import DetectionEngine

    # Initialize the detection engine
    engine = DetectionEngine()

    # Reload and apply rules
    engine.rules = rules
    engine.apply_rules()

    print("Rules applied successfully to the detection engine.")

# Test packets for validation
TEST_PACKETS = [
    {"timestamp": "2025-12-01 12:00:00", "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "protocol": "TCP", "length": 100},
    {"timestamp": "2025-12-01 12:01:00", "src_ip": "192.168.1.2", "dst_ip": "10.0.0.2", "protocol": "UDP", "length": 200},
    {"timestamp": "2025-12-01 12:02:00", "src_ip": "192.168.1.3", "dst_ip": "10.0.0.3", "protocol": "ICMP", "length": 300}
]

if __name__ == "__main__":
    if Flask is None:
        print('Flask not installed; cannot run API')
    else:
        create_app().run(host='127.0.0.1', port=5000)

    from ids.detection.engine import DetectionEngine

    engine = DetectionEngine()
    engine.reload_rules()

    print("Processing test packets...")
    engine.process_packets(TEST_PACKETS)
    print("Test packets processed.")
