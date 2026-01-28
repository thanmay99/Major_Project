# congestion_aware_controller_fixed.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import ipaddress
import networkx as nx
import time
from ryu.lib import hub
from collections import defaultdict
import hashlib
import hmac
import base64
import os
import logging
import random

# Optional AES support
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    AES_AVAILABLE = True
except Exception:
    AES_AVAILABLE = False

# Import your blockchain client and database
from blockchain_client import BlockchainClient
from trust_database import TrustDatabase


# Enhanced Region Trust Manager WITH DEATH SPIRAL FIXES
class EnhancedRegionTrustManager:
    def __init__(self, blockchain=None, queue_fn=None, default_trust=1.0,
                 min_trust=0.1, max_trust=1.0, logger=None, db=None):
        self.trust = {}
        self.default_trust = float(default_trust)
        self.min_trust = float(min_trust)
        self.max_trust = float(max_trust)
        self.blockchain = blockchain
        self.queue_fn = queue_fn
        self.logger = logger or logging.getLogger("EnhancedRegionTrustManager")
        self.db = db
        
        # Enhanced metrics storage
        self.congestion_history = defaultdict(list)
        self.packet_loss_rates = defaultdict(float)
        self.latency_metrics = defaultdict(list)
        self.security_events = defaultdict(int)
        self.flow_completion_rates = defaultdict(list)
        
        # Weights for different trust factors
        self.weights = {
            'congestion': 0.3,
            'packet_loss': 0.25, 
            'latency': 0.2,
            'security': 0.15,
            'reliability': 0.1
        }

        # Load historical trust data on startup
        self._load_historical_trust()

    def _load_historical_trust(self):
        """Load trust scores from database on startup"""
        if self.db:
            try:
                saved_scores = self.db.get_all_trust_scores()
                for region, score in saved_scores.items():
                    self.trust[region] = float(score)
                self.logger.info(f"📂 Loaded historical trust for {len(saved_scores)} regions from database")
                
                # Log statistics
                stats = self.db.get_trust_statistics()
                if stats['total_regions'] > 0:
                    self.logger.info(f"📊 Trust Statistics: Avg={stats['average_trust']}, Min={stats['min_trust']}, Max={stats['max_trust']}")
                
                # FIX: Auto-recover if trust scores are too low (death spiral detection)
                low_trust_regions = [r for r, s in self.trust.items() if s < 0.3]
                if len(low_trust_regions) >= 2:
                    self.logger.warning(f"🚨 DEATH SPIRAL DETECTED: {len(low_trust_regions)} regions with trust < 0.3")
                    self._auto_recover_from_death_spiral(low_trust_regions)
                
            except Exception as e:
                self.logger.warning(f"Could not load trust history from database: {e}")
        else:
            self.logger.info("No database configured - starting with fresh trust scores")

    def _auto_recover_from_death_spiral(self, low_trust_regions):
        """Automatically recover from trust death spiral"""
        self.logger.warning(f"🔄 AUTO-RECOVERY: Boosting trust for {low_trust_regions}")
        for region in low_trust_regions:
            new_trust = min(0.6, self.trust[region] + 0.3)  # Boost but cap at 0.6
            self.set(region, new_trust, "auto_recovery_from_death_spiral")

    def _clamp(self, v):
        return max(self.min_trust, min(self.max_trust, float(v)))

    def get(self, region):
        return float(self.trust.get(region, self.default_trust))

    def _set_local(self, region, new_val):
        nv = self._clamp(new_val)
        self.trust[region] = nv
        return nv

    def _queue_chain_update(self, region, value):
        if self.blockchain and self.queue_fn:
            stored_val = int(value * 100)
            for name in ("update_region_trust", "updateRegionTrust", "setRegionTrust"):
                fn = getattr(self.blockchain, name, None)
                if callable(fn):
                    try:
                        self.queue_fn(fn, region, stored_val)
                    except Exception as e:
                        self.logger.debug("Failed to queue chain trust update for %s: %s", region, e)
                    break

    def set(self, region, value, reason="manual_update"):
        """Set trust score with reason and database persistence"""
        nv = self._set_local(region, value)
        
        # Save to database
        if self.db:
            success = self.db.update_trust_score(region, nv, reason)
            if success:
                self.logger.debug(f"💾 Saved trust update for {region} to database: {nv:.3f} ({reason})")
            else:
                self.logger.warning(f"❌ Failed to save trust update for {region} to database")
        
        self._queue_chain_update(region, nv)
        self.logger.info(f"EnhancedRegionTrustManager: set {region} -> {nv:.3f} ({reason})")
        return nv

    def update_congestion_metric(self, region, utilization):
        """Update congestion history with database logging"""
        current_time = time.time()
        self.congestion_history[region].append((current_time, utilization))
        
        # Save to database
        if self.db:
            self.db.save_region_metric(region, "congestion", utilization)
        
        # Keep only last hour of data
        one_hour_ago = current_time - 3600
        self.congestion_history[region] = [
            (t, u) for t, u in self.congestion_history[region] 
            if t > one_hour_ago
        ]

    def update_packet_loss(self, region, loss_rate):
        """Update packet loss rate with database logging"""
        alpha = 0.7
        old_rate = self.packet_loss_rates.get(region, 0.0)
        self.packet_loss_rates[region] = (alpha * old_rate + (1 - alpha) * loss_rate)
        
        # Save to database
        if self.db:
            self.db.save_region_metric(region, "packet_loss", loss_rate)

    def update_latency(self, region, latency_ms):
        """Update latency metrics with database logging"""
        self.latency_metrics[region].append(latency_ms)
        
        # Save to database
        if self.db:
            self.db.save_region_metric(region, "latency", latency_ms)
        
        if len(self.latency_metrics[region]) > 100:
            self.latency_metrics[region] = self.latency_metrics[region][-50:]

    def record_security_event(self, region, severity=1):
        """Record security event with database logging"""
        self.security_events[region] += severity
        
        # Save to database
        if self.db:
            self.db.save_region_metric(region, "security_event", severity)

    def update_flow_success(self, region, success):
        """Update flow completion success rate with database logging"""
        success_value = 1.0 if success else 0.0
        self.flow_completion_rates[region].append(success_value)
        
        # Save to database
        if self.db:
            self.db.save_region_metric(region, "flow_success", success_value)
        
        if len(self.flow_completion_rates[region]) > 50:
            self.flow_completion_rates[region] = self.flow_completion_rates[region][-50:]

    def calculate_comprehensive_trust(self, region):
        """Calculate trust score using multiple metrics"""
        base_trust = self.get(region)
        
        # 1. Congestion factor
        congestion_score = 1.0
        if region in self.congestion_history:
            recent_congestion = [u for t, u in self.congestion_history[region] 
                               if time.time() - t < 300]
            if recent_congestion:
                avg_congestion = sum(recent_congestion) / len(recent_congestion)
                congestion_score = max(0.1, 1.0 - avg_congestion)

        # 2. Packet loss factor
        loss_score = 1.0
        if region in self.packet_loss_rates:
            loss_rate = self.packet_loss_rates[region]
            loss_score = max(0.1, 1.0 - (loss_rate * 10))

        # 3. Latency factor
        latency_score = 1.0
        if region in self.latency_metrics and self.latency_metrics[region]:
            avg_latency = sum(self.latency_metrics[region]) / len(self.latency_metrics[region])
            if avg_latency <= 100:
                latency_score = 1.0
            elif avg_latency <= 500:
                latency_score = 0.5
            else:
                latency_score = 0.1

        # 4. Security factor
        security_score = 1.0
        if region in self.security_events:
            event_count = self.security_events[region]
            security_score = max(0.1, 1.0 / (1 + event_count * 0.5))

        # 5. Reliability factor
        reliability_score = 1.0
        if region in self.flow_completion_rates and self.flow_completion_rates[region]:
            success_rate = sum(self.flow_completion_rates[region]) / len(self.flow_completion_rates[region])
            reliability_score = success_rate

        # Combine all factors
        comprehensive_trust = (
            self.weights['congestion'] * congestion_score +
            self.weights['packet_loss'] * loss_score +
            self.weights['latency'] * latency_score +
            self.weights['security'] * security_score +
            self.weights['reliability'] * reliability_score
        )

        return self._clamp(comprehensive_trust)

    def penalize(self, region, reason="congestion", severity=1):
        """FIXED: Softer penalties to avoid death spiral"""
        old_trust = self.get(region)
        
        # SOFTER PENALTIES - prevent death spiral
        if reason == "congestion":
            penalty = 0.08 * severity  # Reduced from 0.15
        elif reason == "packet_loss":
            penalty = 0.10 * severity  # Reduced from 0.20
        elif reason == "security":
            penalty = 0.12 * severity  # Reduced from 0.25
            self.record_security_event(region, severity)
        else:
            penalty = 0.05 * severity  # Reduced from 0.10
            
        new_trust = self._clamp(old_trust - penalty)
        
        # SAFETY NET: Don't drop below 0.3 during congestion
        if reason == "congestion" and new_trust < 0.3:
            new_trust = 0.3
            self.logger.warning(f"🛡️ Safety net activated for {region}: trust capped at 0.3")
        
        # Use set method which handles database persistence
        final_trust = self.set(region, new_trust, f"penalty:{reason}:severity_{severity}")
        
        self.logger.info(f"EnhancedRegionTrustManager: penalized {region} for {reason} -> trust={final_trust:.3f}")
        return final_trust

    def reward(self, region, reason="recovery", amount=0.10):
        """FIXED: Larger rewards for faster recovery from low trust"""
        old_trust = self.get(region)
        
        # LARGER REWARDS when trust is low (faster recovery)
        if old_trust < 0.3:
            amount = 0.15  # Larger boost from very low trust
        elif old_trust < 0.6:
            amount = 0.12  # Moderate boost from medium trust
        
        new_trust = self._clamp(old_trust + amount)
        
        # Use set method which handles database persistence
        final_trust = self.set(region, new_trust, f"reward:{reason}")
        
        self.logger.info(f"EnhancedRegionTrustManager: rewarded {region} for {reason} -> trust={final_trust:.3f}")
        return final_trust

    # Database analysis methods
    def get_trust_trends(self, region, hours=24):
        """Get trust score trends over time from database"""
        if self.db:
            return self.db.get_trust_history(region, limit=hours*12)
        return []

    def get_most_problematic_regions(self, limit=5):
        """Get regions with lowest trust from database"""
        if self.db:
            return self.db.get_most_problematic_regions(limit)
        return []

    def print_trust_report(self):
        """Print comprehensive trust report"""
        if not self.db:
            self.logger.info("No database available for trust report")
            return
        
        stats = self.db.get_trust_statistics()
        problematic = self.get_most_problematic_regions(3)
        
        self.logger.info("📊 ======= TRUST REPORT =======")
        self.logger.info(f"📈 Statistics: {stats['total_regions']} regions, Avg Trust: {stats['average_trust']}")
        
        if problematic:
            self.logger.info("🚨 Most Problematic Regions:")
            for region_data in problematic:
                history = self.get_trust_trends(region_data['region'], hours=1)
                recent_change = f" (Recent events: {len(history)})" if history else ""
                self.logger.info(f"   - {region_data['region']}: {region_data['trust_score']:.3f}{recent_change}")
        
        # Show all current trust scores
        self.logger.info("🏷️ Current Trust Scores:")
        for region, score in sorted(self.trust.items(), key=lambda x: x[1], reverse=True):
            status = "🟢" if score > 0.7 else "🟡" if score > 0.4 else "🔴"
            self.logger.info(f"   {status} {region}: {score:.3f}")
        
        self.logger.info("📊 ============================")


class FullyDynamicRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Configurable parameters
    DEFAULT_LINK_CAPACITY_BPS = 100_000_000
    CONGESTION_THRESHOLD = 0.7
    STABLE_PERIOD = 5.0
    MONITOR_INTERVAL = 5.0

    # Packet proofing / encryption config
    ENABLE_PACKET_ENCRYPTION = True
    ENABLE_ALL_PACKET_PROOFS = True
    SECRET_KEY = os.environ.get("CONTROLLER_SECRET_KEY", None)
    
    # Blockchain spam reduction parameters
    PACKET_PROOF_SAMPLING_RATE = 0.1
    ENABLE_SMART_SAMPLING = True
    
    # Packet chaining parameters
    ENABLE_PACKET_CHAINING = True

    def __init__(self, *args, **kwargs):
        super(FullyDynamicRouter, self).__init__(*args, **kwargs)

        # If no secret provided, generate a deterministic one for testing
        if not self.SECRET_KEY:
            fallback = "ryu_controller_fallback_secret_v1"
            self.SECRET_KEY = hashlib.sha256(fallback.encode()).hexdigest()
            self.logger.warning("CONTROLLER_SECRET_KEY not set — using fallback secret (NOT FOR PROD)")

        # Binary secret bytes
        self._master_secret = hashlib.sha256(self.SECRET_KEY.encode()).digest()

        # Initialize Database
        try:
            self.trust_db = TrustDatabase("trust_history.db")
            self.logger.info("✅ Database initialized: trust_history.db")
        except Exception as e:
            self.trust_db = None
            self.logger.error(f"❌ Failed to initialize database: {e}")

        # Blockchain client
        try:
            self.blockchain = BlockchainClient()
            self.logger.info("✅ Connected to Blockchain | Account: %s", getattr(self.blockchain, "account", "unknown"))
        except Exception as e:
            self.blockchain = None
            self.logger.exception("Failed to initialize BlockchainClient: %s", e)

        # Topology & datapaths
        self.gateway_macs = {}
        self.datapaths = {}
        self.network_graph = nx.DiGraph()
        self.subnets = {}
        self.switch_links = {}
        self.switch_ports = {}
        self.host_ports = {}
        self.host_locations = {}
        self.arp_table = {}
        self.mac_to_port = {}
        self.next_gateway_id = 1

        # Link stats
        self.link_stats = defaultdict(lambda: {
            "last_tx_bytes": None,
            "last_ts": None,
            "rate_bps": 0.0,
            "utilization": 0.0,
            "congested": False,
            "pending_since": None
        })

        # Edges to globally avoid when congested
        self.avoided_edges = set()

        # Flow bookkeeping
        self.flow_paths = {}
        self.flow_proof_count = {}
        self.flow_chains = {}

        # Threading
        self.lock = hub.Event()
        self.monitor_thread = hub.spawn(self._monitor_datapaths)

        # Blockchain operation queue
        self.blockchain_queue = hub.Queue(200)
        self.blockchain_worker_thread = hub.spawn(self._process_blockchain_queue)

        # Enhanced Region trust manager WITH FIXES
        self.region_trust = EnhancedRegionTrustManager(
            blockchain=self.blockchain,
            queue_fn=self._queue_blockchain_operation,
            default_trust=1.0,
            min_trust=0.1,
            max_trust=1.0,
            logger=self.logger,
            db=self.trust_db
        )

        # Trust report thread (runs every 5 minutes)
        self.trust_report_thread = hub.spawn(self._periodic_trust_report)
        
        # FIX: Emergency congestion control thread
        self.congestion_control_thread = hub.spawn(self._emergency_congestion_control)

        # Test encryption on startup
        self._test_encryption_capability()

        # Info log
        self.logger.info("🚀 ENHANCED CONGESTION CONTROLLER WITH DEATH SPIRAL FIXES")
        self.logger.info("🛡️ Features: Softer penalties, Faster recovery, Emergency congestion control")
        self.logger.info("AES available: %s; packet encryption enabled: %s", AES_AVAILABLE, self.ENABLE_PACKET_ENCRYPTION)
        self.logger.info("Database: %s", "Enabled" if self.trust_db else "Disabled")

    # NEW: Emergency congestion control to prevent death spiral
    def _emergency_congestion_control(self):
        """Monitor and prevent congestion death spiral"""
        while True:
            hub.sleep(30)  # Check every 30 seconds
            try:
                low_trust_regions = [r for r, score in self.region_trust.trust.items() if score < 0.3]
                
                if len(low_trust_regions) >= 2:  # If multiple regions are congested
                    self.logger.warning(f"🚨 CONGESTION CRISIS: {len(low_trust_regions)} regions with trust < 0.3")
                    
                    # Enable traffic shaping for congested regions
                    for region in low_trust_regions:
                        # Boost trust to break the spiral
                        current_trust = self.region_trust.get(region)
                        if current_trust < 0.4:
                            new_trust = min(0.6, current_trust + 0.25)
                            self.region_trust.set(region, new_trust, "emergency_congestion_recovery")
                            self.logger.info(f"🆘 Emergency boost: {region} -> {new_trust:.3f}")
                    
                    # Log the emergency
                    if self.blockchain:
                        self._queue_blockchain_operation(
                            self.blockchain.log_security_event, 
                            "congestion_crisis", 
                            f"{len(low_trust_regions)} regions in death spiral"
                        )
                        
            except Exception as e:
                self.logger.debug("Emergency congestion control error: %s", e)

    # FIXED: Softer edge weights to prevent over-avoidance
    def _edge_weight(self, u, v):
        stats = self.link_stats.get((u, v), {})
        rate = stats.get("rate_bps", 0.0)
        capacity = self.DEFAULT_LINK_CAPACITY_BPS
        util = 0.0
        if capacity > 0:
            util = min(1.0, rate / float(capacity))
        
        # SOFTER congestion avoidance
        if util >= 0.95:
            base_weight = 50.0  # Reduced from 1000.0
        elif util >= 0.8:
            base_weight = 10.0  # Reduced from 100.0
        else:
            base_weight = 1.0 + util * 2.0  # Much gentler slope

        try:
            region_id = f"s{v}"
            trust = self.region_trust.calculate_comprehensive_trust(region_id)
            trust_factor = max(0.3, trust)  # Minimum trust factor to prevent over-penalty
            weight = base_weight / trust_factor
            return weight
        except Exception:
            return base_weight

    # NEW: Traffic shaping for congested regions
    def _should_allow_cross_region_traffic(self, src_region, dst_region):
        """Intelligent traffic shaping to prevent congestion collapse"""
        src_trust = self.region_trust.get(src_region)
        dst_trust = self.region_trust.get(dst_region)
        
        # If both regions have low trust, apply backpressure
        if src_trust < 0.4 and dst_trust < 0.4:
            allow_probability = 0.4  # Only allow 40% of packets
            self.logger.debug(f"🚧 Traffic shaping: {src_region}->{dst_region} (allow: {allow_probability*100}%)")
            return random.random() < allow_probability
        
        # Allow all traffic if at least one region is healthy
        return True

    # NEW: Emergency trust reset function
    def emergency_trust_reset(self):
        """Manual emergency function to reset trust scores"""
        emergency_regions = ['s1', 's2', 's3']  # Adjust based on your topology
        if self.trust_db:
            success = self.trust_db.emergency_reset_trust(emergency_regions, 0.7)
            if success:
                # Also update in-memory trust scores
                for region in emergency_regions:
                    self.region_trust.trust[region] = 0.7
                self.logger.warning("🆘 EMERGENCY TRUST RESET COMPLETE: All regions set to 0.7")
                return True
        return False

    # Periodic trust reporting
    def _periodic_trust_report(self):
        """Generate trust reports periodically"""
        while True:
            hub.sleep(300)  # Every 5 minutes
            try:
                self.region_trust.print_trust_report()
            except Exception as e:
                self.logger.debug("Error generating trust report: %s", e)

    # Override congestion detection to include database logging
    def _evaluate_congestion_for_link(self, u, v, entry):
        """Decide if a directed link (u->v) is congested with database logging"""
        now = time.time()
        util = entry.get("utilization", 0.0)
        was_congested = entry.get("congested", False)
        pending_since = entry.get("pending_since", None)

        # Transition to congested
        if not was_congested and util >= self.CONGESTION_THRESHOLD:
            if pending_since is None:
                entry["pending_since"] = now
            elif now - pending_since >= self.STABLE_PERIOD:
                entry["congested"] = True
                entry["pending_since"] = None
                self.avoided_edges.add((u, v))
                util_pct = int(util * 100)
                self._on_congestion_detected(u, v, util_pct)
                
                # Log congestion to database via trust manager
                region_id = f"s{v}"
                self.region_trust.update_congestion_metric(region_id, util)
        
        # Transition to recovered
        elif was_congested and util < self.CONGESTION_THRESHOLD:
            if pending_since is None:
                entry["pending_since"] = now
            elif now - pending_since >= self.STABLE_PERIOD:
                entry["congested"] = False
                entry["pending_since"] = None
                if (u, v) in self.avoided_edges:
                    self.avoided_edges.remove((u, v))
                util_pct = int(util * 100)
                self._on_congestion_cleared(u, v, util_pct)
        else:
            entry["pending_since"] = None

    # Add database cleanup on exit (optional)
    def close(self):
        """Cleanup resources when controller stops"""
        if hasattr(self, 'trust_db') and self.trust_db:
            self.trust_db.close()
            self.logger.info("Database connection closed")
        super().close()

    # ========== REST OF YOUR EXISTING CODE ==========
    # [PASTE ALL YOUR EXISTING METHODS FROM YOUR ORIGINAL CONTROLLER HERE]
    # Include ALL these methods exactly as they are in your current controller:

    def _get_chain_context(self, src_ip, dst_ip, packet_data):
        """Get previous hash and create chain context for packet chaining"""
        if not self.ENABLE_PACKET_CHAINING:
            return packet_data.hex()
            
        flow_key = (src_ip, dst_ip)
        
        if flow_key not in self.flow_chains:
            self.flow_chains[flow_key] = "START"
            chain_context = packet_data.hex() + "|START"
            self.logger.info(f"🔗 CHAIN STARTED for {src_ip}->{dst_ip}")
        else:
            previous_hash = self.flow_chains[flow_key]
            chain_context = packet_data.hex() + "|" + previous_hash
            self.logger.debug(f"🔗 CHAIN CONTINUED for {src_ip}->{dst_ip} (prev: {previous_hash[:16]}...)")
            
        return chain_context

    def _update_chain_state(self, src_ip, dst_ip, current_hash):
        """Update the chain state with the current packet's hash"""
        if not self.ENABLE_PACKET_CHAINING:
            return
            
        flow_key = (src_ip, dst_ip)
        self.flow_chains[flow_key] = current_hash

    def _calculate_chain_hash(self, chain_context):
        """Calculate hash of the chain context"""
        return hashlib.sha256(chain_context.encode()).hexdigest()

    def verify_packet_chain(self, src_ip, dst_ip, captured_packets):
        """Verify packet chain integrity (for auditing/forensics)"""
        if not self.ENABLE_PACKET_CHAINING:
            self.logger.warning("Packet chaining not enabled")
            return True
            
        flow_key = (src_ip, dst_ip)
        expected_chain = "START"
        
        for i, packet_data in enumerate(captured_packets):
            chain_context = packet_data.hex() + "|" + expected_chain
            expected_hash = self._calculate_chain_hash(chain_context)
            self.logger.info(f"🔍 Verifying packet {i}: expected_hash={expected_hash[:16]}...")
            expected_chain = expected_hash
        
        self.logger.info("✅ Chain verification completed")
        return True

    def _should_store_packet_proof(self, src_ip, dst_ip, data_length):
        """Smart decision whether to store packet proof"""
        if not self.ENABLE_SMART_SAMPLING:
            return True
            
        flow_key = (src_ip, dst_ip)
        if flow_key not in self.flow_proof_count:
            self.flow_proof_count[flow_key] = 0
            return True
        
        self.flow_proof_count[flow_key] += 1
        
        if data_length > 1000:
            sampling_rate = self.PACKET_PROOF_SAMPLING_RATE * 2
        else:
            sampling_rate = self.PACKET_PROOF_SAMPLING_RATE
        
        if random.random() < sampling_rate:
            return True
        
        if self.flow_proof_count[flow_key] % 10 == 0:
            return True
            
        return False

    def _process_blockchain_queue(self):
        """Process blockchain operations in a separate thread"""
        while True:
            try:
                operation = self.blockchain_queue.get()
                if operation is None:
                    break

                fn, args, kwargs = operation
                try:
                    if self.blockchain and fn is not None:
                        fn(*args, **kwargs)
                except Exception as e:
                    self.logger.debug("Blockchain operation failed: %s", e)
            except Exception as e:
                self.logger.debug("Blockchain queue processing error: %s", e)
            hub.sleep(0.001)

    def _queue_blockchain_operation(self, fn, *args, **kwargs):
        """Queue a blockchain operation for async processing"""
        if not self.blockchain or fn is None:
            return False
            
        if not hasattr(self.blockchain, fn.__name__):
            self.logger.warning(f"Blockchain method {fn.__name__} not available")
            return False

        try:
            self.blockchain_queue.put((fn, args, kwargs), timeout=0.001)
            return True
        except hub.QueueFull:
            self.logger.debug("Blockchain queue full, dropping operation")
            return False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.datapaths[dpid] = dp
        self.switch_ports.setdefault(dpid, set())
        self.host_ports.setdefault(dpid, set())
        self.switch_links.setdefault(dpid, {})

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
        self.add_flow(dp, 0, match, actions)

        self.logger.info("Switch %s connected", dpid)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch_list = get_switch(self, None)
        switches = [switch.dp.id for switch in switch_list]
        self.logger.info("Active switches: %s", switches)

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port = link.src.port_no
        dst_port = link.dst.port_no

        self.switch_links.setdefault(src_dpid, {})[dst_dpid] = src_port
        self.switch_links.setdefault(dst_dpid, {})[src_dpid] = dst_port

        self.switch_ports.setdefault(src_dpid, set()).add(src_port)
        self.switch_ports.setdefault(dst_dpid, set()).add(dst_port)

        self.network_graph.add_node(src_dpid)
        self.network_graph.add_node(dst_dpid)
        self.network_graph.add_edge(src_dpid, dst_dpid, port=src_port)
        self.network_graph.add_edge(dst_dpid, src_dpid, port=dst_port)

        self.link_stats[(src_dpid, dst_dpid)]
        self.link_stats[(dst_dpid, src_dpid)]

        self.logger.info("Link discovered: s%s[p%s] -- s%s[p%s]", src_dpid, src_port, dst_dpid, dst_port)

    def _discover_topology(self):
        try:
            switch_list = get_switch(self, None)
            link_list = get_link(self, None)

            self.network_graph.clear()
            self.switch_links.clear()

            for switch in switch_list:
                dpid = switch.dp.id
                self.network_graph.add_node(dpid)
                self.switch_links.setdefault(dpid, {})

            for link in link_list:
                src = link.src
                dst = link.dst
                self.switch_links[src.dpid][dst.dpid] = src.port_no
                self.switch_links[dst.dpid][src.dpid] = dst.port_no
                self.network_graph.add_edge(src.dpid, dst.dpid, port=src.port_no)
                self.network_graph.add_edge(dst.dpid, src.dpid, port=dst.port_no)

                self.link_stats[(src.dpid, dst.dpid)]
                self.link_stats[(dst.dpid, src.dpid)]

        except Exception as e:
            self.logger.debug("Topology discovery error: %s", e)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if int(time.time()) % 10 == 0:
            self._discover_topology()

        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp_dynamic(dp, in_port, pkt, eth, msg.data)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                self._handle_ipv4_dynamic(dp, in_port, ip_pkt, eth, msg.data)
                return

        self._flood_packet(dp, in_port, msg.data)

    def _handle_arp_dynamic(self, datapath, in_port, pkt, eth, data):
        arp_pkt = pkt.get_protocol(arp.arp)
        if not arp_pkt:
            return
        dpid = datapath.id
        if arp_pkt.src_ip:
            self._learn_host_dynamic(dpid, in_port, arp_pkt.src_ip, arp_pkt.src_mac)

        if arp_pkt.opcode == arp.ARP_REQUEST:
            gw_ip, gw_mac = self._auto_assign_gateway(arp_pkt.src_ip)
            if arp_pkt.dst_ip == gw_ip:
                self._send_arp_reply(datapath, in_port, arp_pkt.src_mac, arp_pkt.src_ip, gw_ip, gw_mac)
                return
            elif arp_pkt.dst_ip in self.host_locations:
                dst_dpid, dst_port, dst_mac = self.host_locations[arp_pkt.dst_ip]
                if dpid == dst_dpid:
                    self._send_arp_reply(datapath, in_port, arp_pkt.src_mac, arp_pkt.src_ip, arp_pkt.dst_ip, dst_mac)
                    return

        self._flood_packet(datapath, in_port, data)

    def _handle_ipv4_dynamic(self, datapath, in_port, ip_pkt, eth, data):
        dpid = datapath.id
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        self._learn_host_dynamic(dpid, in_port, src_ip, eth.src)

        if dst_ip in self.host_locations:
            dst_dpid, dst_port, dst_mac = self.host_locations[dst_ip]
            src_gateway_ip, src_gateway_mac = self._auto_assign_gateway(src_ip)
            if dpid == dst_dpid:
                self._send_packet_direct(datapath, in_port, dst_mac, dst_port, data, src_ip, dst_ip)
            else:
                # FIXED: Apply traffic shaping for congested regions
                src_region = f"s{src_dpid}" if hasattr(src_dpid, 'dpid') else f"s{src_dpid}"
                dst_region = f"s{dst_dpid}" if hasattr(dst_dpid, 'dpid') else f"s{dst_dpid}"
                
                if self._should_allow_cross_region_traffic(src_region, dst_region):
                    next_port = self._get_next_hop(dpid, dst_dpid, flow_src_ip=src_ip, flow_dst_ip=dst_ip)
                    if next_port:
                        self._send_packet_routed(datapath, in_port, src_gateway_mac, dst_mac, next_port, data, src_ip, dst_ip)
                        self._install_cross_subnet_flow_dynamic(src_ip, dst_ip)
                    else:
                        self._flood_packet(datapath, in_port, data, src_ip, dst_ip)
                else:
                    self.logger.debug(f"🚧 Traffic shaped: Blocked {src_region}->{dst_region} due to congestion")
        else:
            src_gateway_ip, src_gateway_mac = self._auto_assign_gateway(src_ip)
            self._send_packet_gateway(datapath, in_port, src_gateway_mac, data, src_ip, dst_ip)

    def _auto_assign_gateway(self, ip):
        network = ipaddress.ip_network(ip + '/24', strict=False)
        subnet = str(network)
        if subnet not in self.subnets:
            gateway_ip = str(network.network_address + 1)
            gateway_mac = "00:dc:00:00:%02x:01" % self.next_gateway_id
            self.subnets[subnet] = gateway_ip
            self.gateway_macs[gateway_ip] = gateway_mac
            self.next_gateway_id += 1
            self.logger.info("Auto-assigned gateway %s for subnet %s", gateway_ip, subnet)
        return self.subnets[subnet], self.gateway_macs[self.subnets[subnet]]

    def _learn_host_dynamic(self, dpid, port, src_ip, src_mac):
        if not self._is_switch_port(dpid, port):
            self.host_ports.setdefault(dpid, set()).add(port)

        old = self.host_locations.get(src_ip)
        if old != (dpid, port, src_mac):
            self.host_locations[src_ip] = (dpid, port, src_mac)
            self.arp_table[src_ip] = src_mac
            self.mac_to_port[(dpid, src_mac)] = port
            gw_ip, gw_mac = self._auto_assign_gateway(src_ip)
            self.logger.info("Learned host: %s at s%s[p%s] -> Gateway: %s", src_ip, dpid, port, gw_ip)
            self._install_dynamic_flows(src_ip, dpid, port, src_mac, gw_ip, gw_mac)
        return True

    def _install_dynamic_flows(self, ip, dpid, port, mac, gateway_ip, gateway_mac):
        dp = self.datapaths.get(dpid)
        if not dp:
            return
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match = parser.OFPMatch(eth_dst=mac)
        actions = [parser.OFPActionOutput(port)]
        self.add_flow(dp, 10, match, actions, idle_timeout=300)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
        actions = [parser.OFPActionSetField(eth_dst=mac), parser.OFPActionOutput(port)]
        self.add_flow(dp, 20, match, actions, idle_timeout=300)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=gateway_ip)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
        self.add_flow(dp, 30, match, actions, idle_timeout=300)

    def _install_cross_subnet_flow_dynamic(self, src_ip, dst_ip):
        if dst_ip not in self.host_locations or src_ip not in self.host_locations:
            return
        src_dpid, src_port, src_mac = self.host_locations[src_ip]
        dst_dpid, dst_port, dst_mac = self.host_locations[dst_ip]
        src_gateway_ip, src_gateway_mac = self._auto_assign_gateway(src_ip)

        if src_dpid == dst_dpid:
            dp = self.datapaths.get(src_dpid)
            if dp:
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                actions = [parser.OFPActionSetField(eth_src=src_gateway_mac),
                           parser.OFPActionSetField(eth_dst=dst_mac),
                           parser.OFPActionOutput(dst_port)]
                self.add_flow(dp, 15, match, actions, idle_timeout=300)
            return

        path = self._find_shortest_path(src_dpid, dst_dpid, avoid_edges=self.avoided_edges)
        if not path:
            return

        for idx in range(len(path) - 1):
            cur = path[idx]
            nxt = path[idx + 1]
            out_port = self.switch_links.get(cur, {}).get(nxt)
            dp = self.datapaths.get(cur)
            if not dp or out_port is None:
                continue
            parser = dp.ofproto_parser
            match_forward = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
            actions_forward = [parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 50, match_forward, actions_forward, idle_timeout=60, hard_timeout=120)
            if idx == 0:
                src_info = self.host_locations.get(src_ip)
                if src_info and src_info[0] == cur:
                    rev_out = src_info[1]
                else:
                    rev_out = None
            else:
                prev = path[idx - 1]
                rev_out = self.switch_links.get(cur, {}).get(prev)
            if rev_out is not None:
                match_rev = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=dst_ip, ipv4_dst=src_ip)
                actions_rev = [parser.OFPActionOutput(rev_out)]
                self.add_flow(dp, 50, match_rev, actions_rev, idle_timeout=60, hard_timeout=120)

        self.flow_paths[(src_ip, dst_ip)] = path
        self.logger.info("📝 Installed path for %s -> %s : %s", src_ip, dst_ip, path)

        flow_id = f"{src_ip}->{dst_ip}:{int(time.time())}"
        path_str = ",".join(str(x) for x in path)
        if self.blockchain:
            for name in ("create_flow_record", "createFlowRecord"):
                fn = getattr(self.blockchain, name, None)
                if callable(fn):
                    self._queue_blockchain_operation(fn, flow_id, src_ip, dst_ip, path_str, "normal")
                    break

    def _monitor_datapaths(self):
        while True:
            try:
                for dp in list(self.datapaths.values()):
                    parser = dp.ofproto_parser
                    req = parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)
                    dp.send_msg(req)
            except Exception as e:
                self.logger.debug("Monitor error: %s", e)
            hub.sleep(self.MONITOR_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        now = time.time()
        neighbor_by_port = {port: nbr for nbr, port in self.switch_links.get(dpid, {}).items()}
        for stat in ev.msg.body:
            port_no = stat.port_no
            if port_no in neighbor_by_port:
                nbr = neighbor_by_port[port_no]
                key = (dpid, nbr)
                entry = self.link_stats[key]
                tx_bytes = getattr(stat, 'tx_bytes', 0)
                last_bytes = entry["last_tx_bytes"]
                last_ts = entry["last_ts"]

                if last_bytes is not None and last_ts is not None and now > last_ts:
                    delta_bytes = max(0, tx_bytes - last_bytes)
                    delta_t = now - last_ts
                    rate_bps = (delta_bytes * 8.0) / delta_t
                    entry["rate_bps"] = rate_bps
                else:
                    entry["rate_bps"] = entry.get("rate_bps", 0.0)

                entry["last_tx_bytes"] = tx_bytes
                entry["last_ts"] = now

                capacity = self.DEFAULT_LINK_CAPACITY_BPS
                utilization = 0.0
                if capacity > 0:
                    utilization = min(1.0, entry["rate_bps"] / float(capacity))
                entry["utilization"] = utilization

                self._evaluate_congestion_for_link(dpid, nbr, entry)

                try:
                    region_id = f"s{nbr}"
                    self.region_trust.update_congestion_metric(region_id, utilization)
                    
                    if entry.get("congested", False):
                        self.region_trust.penalize(region_id, reason="congestion")
                    else:
                        self.region_trust.reward(region_id, reason="recovery", amount=0.05)
                except Exception as e:
                    self.logger.debug("Enhanced region trust update failed for %s: %s", nbr, e)

        try:
            summary = []
            for u, v, data in self.network_graph.edges(data=True):
                util = self.link_stats.get((u, v), {}).get("utilization", 0.0)
                summary.append("s{}-s{}:{:.0f}%".format(u, v, util * 100))
            if summary:
                self.logger.info("Link utilization summary: %s", " | ".join(summary))
        except Exception:
            pass

    def _on_congestion_detected(self, u, v, util_pct):
        self.logger.warning("⚠️ Congestion detected on path s{}–s{} ({}%) → rerouting via alternate path".format(u, v, util_pct))
        if self.blockchain:
            self._queue_blockchain_operation(self.blockchain.log_congestion_event, f"s{u}-s{v}", util_pct, "reroute")
            self.logger.info("🧱 Blockchain entry queued for congestion: s%s–s%s", u, v)
        self._reinstall_all_flows_avoiding((u, v))

    def _on_congestion_cleared(self, u, v, util_pct):
        self.logger.info("✅ Congestion cleared on path s{}–s{} ({}%) → reverting to direct path s{}–s{}".format(u, v, util_pct, u, v))
        if self.blockchain:
            self._queue_blockchain_operation(self.blockchain.log_congestion_event, f"s{u}-s{v}", util_pct, "clear")
            self.logger.info("🧱 Blockchain entry queued for clearance: s%s–s%s", u, v)
        self._reinstall_all_flows_avoiding(None)

    def _reinstall_all_flows_avoiding(self, avoid_edge):
        for src_ip, src_info in list(self.host_locations.items()):
            for dst_ip, dst_info in list(self.host_locations.items()):
                if src_ip == dst_ip:
                    continue
                src_net = ipaddress.ip_network(src_ip + '/24', strict=False)
                dst_net = ipaddress.ip_network(dst_ip + '/24', strict=False)
                if src_net == dst_net:
                    continue
                try:
                    self._install_cross_subnet_flow_dynamic(src_ip, dst_ip)
                except Exception as e:
                    self.logger.debug("Failed reinstalling flow %s->%s: %s", src_ip, dst_ip, e)

    def _find_shortest_path(self, src_dpid, dst_dpid, avoid_edges=None):
        if avoid_edges is None:
            avoid_edges = set()
        if src_dpid not in self.network_graph or dst_dpid not in self.network_graph:
            return None
        temp = self.network_graph.copy()
        for (u, v) in avoid_edges:
            if temp.has_edge(u, v):
                temp.remove_edge(u, v)
        def weight(u, v, data):
            return self._edge_weight(u, v)
        try:
            path = nx.shortest_path(temp, src_dpid, dst_dpid, weight=weight)
            return path
        except nx.NetworkXNoPath:
            return None

    def _get_next_hop(self, src_dpid, dst_dpid, flow_src_ip=None, flow_dst_ip=None):
        if src_dpid not in self.network_graph or dst_dpid not in self.network_graph:
            return None
        path = self._find_shortest_path(src_dpid, dst_dpid, avoid_edges=self.avoided_edges)
        if not path or len(path) < 2:
            return None
        next_hop = path[1]
        return self.switch_links.get(src_dpid, {}).get(next_hop)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def _send_packet_direct(self, datapath, in_port, dst_mac, out_port, data, src_ip=None, dst_ip=None):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        if self.ENABLE_ALL_PACKET_PROOFS and self.blockchain and data and src_ip and dst_ip:
            if self._should_store_packet_proof(src_ip, dst_ip, len(data)):
                self.logger.info(f"🎯 DIRECT PACKET PROOF: {src_ip} -> {dst_ip}")
                self._process_packet_proof(data, src_ip, dst_ip)

    def _send_packet_routed(self, datapath, in_port, gw_mac, dst_mac, out_port, data, src_ip, dst_ip):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        actions = [parser.OFPActionSetField(eth_src=gw_mac),
                   parser.OFPActionSetField(eth_dst=dst_mac),
                   parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        if self.blockchain and data:
            if self._should_store_packet_proof(src_ip, dst_ip, len(data)):
                self.logger.info(f"🎯 ROUTED PACKET PROOF: {src_ip} -> {dst_ip}")
                self._process_packet_proof(data, src_ip, dst_ip)

    def _send_packet_gateway(self, datapath, in_port, gw_mac, data, src_ip=None, dst_ip=None):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        actions = [parser.OFPActionSetField(eth_src=gw_mac),
                   parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        if self.ENABLE_ALL_PACKET_PROOFS and self.blockchain and data and src_ip and dst_ip:
            if self._should_store_packet_proof(src_ip, dst_ip, len(data)):
                self.logger.info(f"🎯 GATEWAY PACKET PROOF: {src_ip} -> {dst_ip}")
                self._process_packet_proof(data, src_ip, dst_ip)

    def _flood_packet(self, datapath, in_port, data, src_ip=None, dst_ip=None):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        if self.ENABLE_ALL_PACKET_PROOFS and self.blockchain and data and src_ip and dst_ip:
            if self._should_store_packet_proof(src_ip, dst_ip, len(data)):
                self.logger.info(f"🎯 FLOODED PACKET PROOF: {src_ip} -> {dst_ip}")
                self._process_packet_proof(data, src_ip, dst_ip)

    def _process_packet_proof(self, data, src_ip, dst_ip):
        try:
            if not self.blockchain:
                return

            self.logger.info(f"🔍 PROCESSING PACKET PROOF: {src_ip} -> {dst_ip}")

            chain_context = self._get_chain_context(src_ip, dst_ip, data)
            chain_hash = self._calculate_chain_hash(chain_context)
            self._update_chain_state(src_ip, dst_ip, chain_hash)

            try:
                network = ipaddress.ip_network(src_ip + "/24", strict=False)
            except Exception:
                network = src_ip + "/24"
            subnet = str(network)

            key = self._derive_subnet_key(subnet)
            packet_hmac = hmac.new(key, chain_context.encode(), hashlib.sha256).hexdigest()

            if self.ENABLE_PACKET_CHAINING:
                chain_parts = chain_context.split('|')
                previous_hash = chain_parts[-1] if len(chain_parts) > 1 else "START"
                proof_plain = "{}|{}|chain:{}".format(chain_hash, packet_hmac, previous_hash)
                self.logger.info(f"🔗 CHAIN PROOF: {src_ip}->{dst_ip} (prev: {previous_hash[:16]}...)")
            else:
                proof_plain = "{}|{}".format(chain_hash, packet_hmac)

            if self.ENABLE_PACKET_ENCRYPTION and AES_AVAILABLE:
                try:
                    cipher_blob = self._encrypt_proof(key, proof_plain.encode())
                    proof_value = "ENC:" + base64.b64encode(cipher_blob).decode()
                    self.logger.info(f"🔐 ENCRYPTED PROOF: {src_ip}->{dst_ip} (len={len(proof_value)})")
                except Exception as e:
                    self.logger.warning(f"🔓 ENCRYPTION FAILED, using plaintext: {e}")
                    proof_value = "PLAINTEXT:" + proof_plain
            else:
                if self.ENABLE_PACKET_ENCRYPTION and not AES_AVAILABLE:
                    self.logger.warning("🔓 AES library not available. Storing plaintext HMAC proof.")
                proof_value = "PLAINTEXT:" + proof_plain
                self.logger.info(f"🔓 PLAINTEXT PROOF: {src_ip}->{dst_ip}")

            if self.blockchain and hasattr(self.blockchain, 'store_packet_proof'):
                success = self._queue_blockchain_operation(self.blockchain.store_packet_proof, src_ip, dst_ip, proof_value)
                if success:
                    self.logger.info(f"📦 PACKET PROOF QUEUED: {src_ip}->{dst_ip}")
                else:
                    self.logger.warning(f"❌ FAILED TO QUEUE PACKET PROOF: {src_ip}->{dst_ip}")
            else:
                self.logger.warning("Blockchain client or store_packet_proof method not available")

        except Exception as e:
            self.logger.error(f"❌ PACKET PROOF PROCESSING FAILED: {e}")

    def _encrypt_proof(self, key_bytes: bytes, plaintext: bytes) -> bytes:
        if not AES_AVAILABLE:
            raise RuntimeError("AES (pycryptodome) not available")
        if len(key_bytes) < 32:
            key = hashlib.sha256(key_bytes).digest()
        else:
            key = key_bytes[:32]
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + tag + ct

    def _decrypt_proof(self, key_bytes: bytes, blob: bytes) -> bytes:
        if not AES_AVAILABLE:
            raise RuntimeError("AES (pycryptodome) not available")
        if len(blob) < 28:
            raise ValueError("invalid blob")
        if len(key_bytes) < 32:
            key = hashlib.sha256(key_bytes).digest()
        else:
            key = key_bytes[:32]
        nonce = blob[0:12]
        tag = blob[12:28]
        ct = blob[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ct, tag)
        return plaintext

    def _derive_subnet_key(self, subnet_str: str) -> bytes:
        return hmac.new(self._master_secret, subnet_str.encode(), hashlib.sha256).digest()

    def _send_arp_reply(self, datapath, port, dst_mac, dst_ip, src_gw_ip, gw_mac):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        e = ethernet.ethernet(dst_mac, gw_mac, ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REPLY, src_mac=gw_mac, src_ip=src_gw_ip,
                   dst_mac=dst_mac, dst_ip=dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=ofp.OFPP_CONTROLLER, actions=actions, data=p.data)
        datapath.send_msg(out)

    def _is_switch_port(self, dpid, port):
        return any(port == link_port for link_port in self.switch_links.get(dpid, {}).values())

    def _test_encryption_capability(self):
        try:
            if self.ENABLE_PACKET_ENCRYPTION and AES_AVAILABLE:
                test_key = b"test_key_32_bytes_123456789012"
                test_data = b"encryption_test_data"
                encrypted = self._encrypt_proof(test_key, test_data)
                decrypted = self._decrypt_proof(test_key, encrypted)
                if decrypted == test_data:
                    self.logger.info("✅ ENCRYPTION TEST PASSED - AES working correctly")
                else:
                    self.logger.error("❌ ENCRYPTION TEST FAILED - Decryption mismatch")
            else:
                self.logger.warning("🔓 ENCRYPTION DISABLED - Using plaintext HMAC proofs")
        except Exception as e:
            self.logger.error(f"❌ ENCRYPTION TEST ERROR: {e}")