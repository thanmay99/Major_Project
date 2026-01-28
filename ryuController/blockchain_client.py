# blockchain_client_fixed.py
from web3 import Web3
import json
from ryu.lib import hub  # Use Ryu's hub instead of threading

class BlockchainClient:
    def __init__(self,
                 contract_address="0xe78A0F7E598Cc8b0Bb87894B0F60dD2a88d6a8Ab",
                 abi_path="/home/thanmay/blockchain-sdn/build/contracts/SDNSecurity.json"):
        try:
            # Connect to local Ganache blockchain
            self.web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
            if not self.web3.is_connected():
                print("❌ Blockchain connection failed! Check Ganache is running.")
                return

            self.account = self.web3.eth.accounts[0]
            self.contract_address = Web3.to_checksum_address(contract_address)

            # Load contract ABI
            with open(abi_path, "r") as abi_file:
                contract_json = json.load(abi_file)
                contract_abi = contract_json["abi"]

            # Initialize contract
            self.contract = self.web3.eth.contract(
                address=self.contract_address,
                abi=contract_abi
            )

            print(f"✅ Connected to Blockchain | Account: {self.account}")
        except Exception as e:
            print(f"⚠️ Blockchain initialization error: {e}")

    def _ensure_connection(self):
        """Ensure blockchain connection is active"""
        if not self.web3.is_connected():
            print("🔄 Reconnecting to blockchain...")
            self.web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))

    # ----------------------------------------------------------
    # Record a flow creation event
    # ----------------------------------------------------------
    def create_flow_record(self, flow_id, src, dst, path, security_level="Normal"):
        def task():
            try:
                self._ensure_connection()
                tx_hash = self.contract.functions.createFlowRecord(
                    flow_id, src, dst, path, security_level
                ).transact({
                    'from': self.account,
                    'gas': 300000,
                    'gasPrice': self.web3.eth.gas_price
                })
                print(f"🟢 Flow tx sent: {tx_hash.hex()[:16]}...")
            except Exception as e:
                print(f"⚠️ Error storing flow record: {e}")
        hub.spawn(task)

    # ----------------------------------------------------------
    # Record a congestion event
    # ----------------------------------------------------------
    def log_congestion_event(self, path, utilization, action):
        def task():
            try:
                self._ensure_connection()
                tx_hash = self.contract.functions.logCongestionEvent(
                    path, int(utilization), action
                ).transact({
                    'from': self.account,
                    'gas': 200000,
                    'gasPrice': self.web3.eth.gas_price
                })
                print(f"🟠 Congestion tx sent: {tx_hash.hex()[:16]}...")
            except Exception as e:
                print(f"⚠️ Error logging congestion event: {e}")
        hub.spawn(task)

    # ----------------------------------------------------------
    # Record a security event (optional)
    # ----------------------------------------------------------
    def log_security_event(self, event_type, event_data):
        def task():
            try:
                self._ensure_connection()
                tx_hash = self.contract.functions.logSecurityEvent(
                    event_type, event_data
                ).transact({
                    'from': self.account,
                    'gas': 200000,
                    'gasPrice': self.web3.eth.gas_price
                })
                print(f"🔐 Security tx sent: {tx_hash.hex()[:16]}...")
            except Exception as e:
                print(f"⚠️ Error logging security event: {e}")
        hub.spawn(task)

    # ----------------------------------------------------------
    # Store packet proof (FIXED - non-blocking)
    # ----------------------------------------------------------
    def store_packet_proof(self, src_ip, dst_ip, packet_hash):
        def task():
            try:
                self._ensure_connection()
                tx_hash = self.contract.functions.storePacketProof(
                    src_ip, dst_ip, packet_hash
                ).transact({
                    'from': self.account,
                    'gas': 250000,
                    'gasPrice': self.web3.eth.gas_price
                })
                # Extract first few chars of hash for logging
                hash_preview = packet_hash[:20] + "..." if len(packet_hash) > 20 else packet_hash
                print(f"📦 Packet proof tx sent: {tx_hash.hex()[:16]}... | Proof: {hash_preview}")
            except Exception as e:
                print(f"⚠️ Error storing packet proof: {e}")
        hub.spawn(task)

    # ----------------------------------------------------------
    # Additional utility methods
    # ----------------------------------------------------------
    def get_packet_proof_count(self):
        """Get count of stored packet proofs"""
        try:
            self._ensure_connection()
            count = self.contract.functions.getPacketProofCount().call()
            return count
        except Exception as e:
            print(f"⚠️ Error getting packet proof count: {e}")
            return 0

    def get_flow_info(self, flow_id):
        """Get flow information"""
        try:
            self._ensure_connection()
            info = self.contract.functions.getFlowInfo(flow_id).call()
            return info
        except Exception as e:
            print(f"⚠️ Error getting flow info: {e}")
            return None