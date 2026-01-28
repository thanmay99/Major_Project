#!/usr/bin/env python3
"""
Blockchain Microservice for SDN Controller
Run this FIRST before starting the Ryu controller
"""

from flask import Flask, request, jsonify
import hashlib
import json
import time
import os
from datetime import datetime

app = Flask(__name__)

class BlockchainLogger:
    def __init__(self):
        self.log_file = '/tmp/sdn_blockchain_logs.txt'
        self.contract_address = "0xe78A0F7E598Cc8b0Bb87894B0F60dD2a88d6a8Ab"
        
    def create_transaction_hash(self, event_data):
        """Create a simulated transaction hash"""
        timestamp = str(time.time())
        unique_string = f"{event_data}{timestamp}{self.contract_address}"
        return hashlib.sha256(unique_string.encode()).hexdigest()
    
    def log_to_blockchain(self, event_type, data):
        """Simulate blockchain transaction logging"""
        try:
            transaction_hash = self.create_transaction_hash(data)
            
            log_entry = {
                "transaction_hash": transaction_hash,
                "event_type": event_type,
                "data": data,
                "timestamp": time.time(),
                "human_time": datetime.now().isoformat(),
                "contract_address": self.contract_address,
                "status": "CONFIRMED",
                "block_number": int(time.time() * 1000) % 1000000
            }
            
            # Log to console
            print(f"🔗 [BLOCKCHAIN] {event_type} | TX: {transaction_hash[:16]}... | Time: {log_entry['human_time']}")
            
            # Save to file (simulating blockchain storage)
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            return {
                "status": "success",
                "transaction_hash": transaction_hash,
                "block_number": log_entry["block_number"],
                "contract_address": self.contract_address
            }
            
        except Exception as e:
            print(f"❌ Blockchain logging error: {e}")
            return {"status": "error", "message": str(e)}

# Initialize blockchain logger
blockchain = BlockchainLogger()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "SDN Blockchain Logger",
        "timestamp": time.time()
    })

@app.route('/log_event', methods=['POST'])
def log_event():
    """Main endpoint for logging SDN events to blockchain"""
    try:
        data = request.json
        
        if not data:
            return jsonify({"status": "error", "message": "No JSON data provided"}), 400
            
        event_type = data.get('event_type')
        event_data = data.get('data')
        
        if not event_type:
            return jsonify({"status": "error", "message": "event_type is required"}), 400
        
        # Log to blockchain
        result = blockchain.log_to_blockchain(event_type, event_data)
        
        if result["status"] == "success":
            return jsonify(result), 200
        else:
            return jsonify(result), 500
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/get_logs', methods=['GET'])
def get_logs():
    """Endpoint to retrieve blockchain logs (for debugging)"""
    try:
        if os.path.exists('/tmp/sdn_blockchain_logs.txt'):
            with open('/tmp/sdn_blockchain_logs.txt', 'r') as f:
                logs = [json.loads(line) for line in f.readlines()]
            return jsonify({"status": "success", "logs": logs[-10:]})  # Last 10 logs
        else:
            return jsonify({"status": "success", "logs": []})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting SDN Blockchain Service...")
    print("📍 Endpoints:")
    print("   - Health: http://localhost:5000/health")
    print("   - Log Event: http://localhost:5000/log_event (POST)")
    print("   - Get Logs: http://localhost:5000/get_logs (GET)")
    print("🔗 Log file: /tmp/sdn_blockchain_logs.txt")
    print("=" * 50)
    
    # Create log file if it doesn't exist
    open('/tmp/sdn_blockchain_logs.txt', 'a').close()
    
    app.run(host='0.0.0.0', port=5000, debug=False)