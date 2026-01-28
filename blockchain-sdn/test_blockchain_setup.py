#!/usr/bin/env python33
from web3 import Web3
import json
import os
import requests

def test_blockchain_connection():
    print("🧪 Testing Blockchain Connection...")
    
    try:
        # Test basic connection
        w3 = Web3(Web3.HTTPProvider('http://localhost:7545'))
        
        if w3.is_connected():
            print("✅ Connected to blockchain")
            print(f"📋 Accounts: {len(w3.eth.accounts)}")
            print(f"⛓️  Chain ID: {w3.eth.chain_id}")
            print(f"🔢 Latest block: {w3.eth.block_number}")
            
            # Show first account details
            if w3.eth.accounts:
                account = w3.eth.accounts[0]
                balance = w3.eth.get_balance(account)
                balance_eth = w3.from_wei(balance, 'ether')
                print(f"�� First account: {account}")
                print(f"💵 Balance: {balance_eth} ETH")
            
            return True
        else:
            print("❌ Not connected to blockchain")
            return False
            
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False

def test_contract_deployment():
    print("\n📦 Checking Contract Deployment...")
    
    contract_path = "build/contracts/SDNSecurity.json"
    if os.path.exists(contract_path):
        try:
            with open(contract_path, 'r') as f:
                contract_data = json.load(f)
            
            networks = contract_data.get('networks', {})
            if networks:
                print("✅ Contract deployment data found:")
                for network_id, deployment in networks.items():
                    address = deployment.get('address')
                    if address:
                        print(f"   🏷️  Network: {network_id}")
                        print(f"   📍 Address: {address}")
                        print(f"   📝 Tx Hash: {deployment.get('transactionHash', 'N/A')}")
                        
                        # Test contract interaction
                        try:
                            w3 = Web3(Web3.HTTPProvider('http://localhost:7545'))
                            if w3.is_connected() and address:
                                # Check if contract exists at address
                                code = w3.eth.get_code(address)
                                if code != '0x':
                                    print(f"   ✅ Contract code deployed: Yes")
                                else:
                                    print(f"   ❌ No contract code at address")
                        except Exception as e:
                            print(f"   ⚠️  Could not verify contract: {e}")
                    else:
                        print(f"   ❌ No address for network {network_id}")
            else:
                print("❌ No deployment networks found in contract file")
                
        except Exception as e:
            print(f"❌ Error reading contract file: {e}")
    else:
        print("❌ Contract build file not found at build/contracts/SDNSecurity.json")

if __name__ == "__main__":
    print("🚀 Blockchain SDN Deployment Test")
    print("=" * 40)
    
    # Test connection
    if test_blockchain_connection():
        # Test contract deployment
        test_contract_deployment()
    else:
        print("\n💡 Make sure blockchain is running: ./start_blockchain.sh")
