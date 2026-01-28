#!/usr/bin/env python3
from web3 import Web3
import json
import os

def test_deployment():
    print("🧪 Testing Blockchain Deployment...")
    
    # Connect to Ganache
    w3 = Web3(Web3.HTTPProvider('http://localhost:7545'))
    
    if not w3.is_connected():
        print("❌ Cannot connect to blockchain")
        return False
    
    print(f"✅ Connected to blockchain")
    print(f"📋 Accounts: {len(w3.eth.accounts)}")
    print(f"⛓️  Chain ID: {w3.eth.chain_id}")
    
    # Check if contract was deployed
    contract_path = "build/contracts/SDNSecurity.json"
    if os.path.exists(contract_path):
        with open(contract_path, 'r') as f:
            contract_data = json.load(f)
            networks = contract_data.get('networks', {})
            if networks:
                print("✅ Contract deployment data found:")
                for network_id, deployment in networks.items():
                    address = deployment.get('address')
                    if address:
                        print(f"   Network {network_id}: {address}")
                        print(f"   📝 Transaction: {deployment.get('transactionHash')}")
                    else:
                        print(f"   Network {network_id}: No address")
            else:
                print("❌ No deployment networks found")
    else:
        print("❌ Contract build file not found")
    
    return True

if __name__ == "__main__":
    test_deployment()