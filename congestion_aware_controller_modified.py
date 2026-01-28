# congestion_aware_controller_blockchain.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub

import ipaddress
import networkx as nx
import time
from collections import defaultdict
import hashlib
import json
import requests

class FullyDynamicRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Configurable parameters
    DEFAULT_LINK_CAPACITY_BPS = 10_000_000
    CONGESTION_THRESHOLD = 0.7
    STABLE_PERIOD = 5.0
    MONITOR_INTERVAL = 5.0

    def __init__(self, *args, **kwargs):
        super(FullyDynamicRouter, self).__init__(*args, **kwargs)
        
        # SDN initialization
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

        self.link_stats = defaultdict(lambda: {
            "last_tx_bytes": None, "last_ts": None, "rate_bps": 0.0,
            "utilization": 0.0, "congested": False, "pending_since": None
        })

        self.avoided_edges = set()
        self.flow_paths = {}
        self.flow_security = {}

        # Blockchain configuration
        self.blockchain_enabled = True
        self.blockchain_url = "http://localhost:5000/log_event"
        self.blockchain_timeout = 2
        
        self.monitor_thread = hub.spawn(self._monitor_datapaths)

        self.logger.info("🚀 SDN Controller with Blockchain API Initialized")

    # Blockchain Communication Methods
    def _log_to_blockchain(self, event_type, data):
        """Send event to blockchain microservice"""
        if not self.blockchain_enabled:
            return self._log_locally(event_type, data)
            
        try:
            payload = {
                "event_type": event_type,
                "data": data
            }
            
            response = requests.post(
                self.blockchain_url,
                json=payload,
                timeout=self.blockchain_timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    self.logger.info(f"🔗 Blockchain logged: {event_type} | TX: {result['transaction_hash'][:16]}...")
                    return True
                else:
                    self.logger.warning(f"🔗 Blockchain service error: {result.get('message')}")
                    
        except requests.exceptions.ConnectionError:
            self.logger.debug("🔗 Blockchain service unreachable - falling back to local logging")
        except requests.exceptions.Timeout:
            self.logger.debug("🔗 Blockchain service timeout - falling back to local logging")
        except Exception as e:
            self.logger.debug(f"🔗 Blockchain communication error: {e}")
        
        return self._log_locally(event_type, data)

    def _log_locally(self, event_type, data):
        """Fallback local logging"""
        try:
            log_entry = {
                "event_type": event_type,
                "data": data,
                "timestamp": time.time(),
                "status": "LOCAL_FALLBACK"
            }
            
            self.logger.info(f"🔗 [BLOCKCHAIN-FALLBACK] {event_type}: {json.dumps(data)}")
            
            with open('/tmp/sdn_local_logs.txt', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
            return True
        except Exception as e:
            self.logger.debug(f"Local logging failed: {e}")
            return False

    def _log_congestion_to_blockchain(self, path, utilization, action):
        return self._log_to_blockchain("CONGESTION_EVENT", {
            "path": path,
            "utilization": utilization,
            "action": action,
            "timestamp": time.time()
        })

    def _create_secure_flow_context(self, src_ip, dst_ip, path):
        flow_key = (src_ip, dst_ip)
        security_context = {
            "flow_id": hashlib.md5(f"{src_ip}-{dst_ip}-{time.time()}".encode()).hexdigest(),
            "path": path,
            "created_at": time.time(),
            "security_level": "HIGH"
        }
        
        self.flow_security[flow_key] = security_context
        
        self._log_to_blockchain("FLOW_CREATED", {
            "flow_id": security_context["flow_id"],
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "path": path,
            "security_level": "HIGH"
        })
        
        return security_context

    # Switch & Topology handlers
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
        self._log_to_blockchain("SWITCH_CONNECTED", {"dpid": dpid, "timestamp": time.time()})

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
        self._log_to_blockchain("LINK_ADDED", {
            "src_dpid": src_dpid, "dst_dpid": dst_dpid, "src_port": src_port, "dst_port": dst_port
        })

    # Packet-in handling
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

        self._log_to_blockchain("PACKET_RECEIVED", {
            "src_ip": src_ip, "dst_ip": dst_ip, "switch": dpid, "port": in_port, "protocol": "IPv4"
        })

        if dst_ip in self.host_locations:
            dst_dpid, dst_port, dst_mac = self.host_locations[dst_ip]
            src_gateway_ip, src_gateway_mac = self._auto_assign_gateway(src_ip)
            
            if dpid == dst_dpid:
                self._send_packet_direct(datapath, in_port, dst_mac, dst_port, data)
            else:
                next_port = self._get_next_hop(dpid, dst_dpid, flow_src_ip=src_ip, flow_dst_ip=dst_ip)
                if next_port:
                    self._send_packet_routed(datapath, in_port, src_gateway_mac, dst_mac, next_port, data)
                    self._install_secure_cross_subnet_flow(src_ip, dst_ip)
                else:
                    self._flood_packet(datapath, in_port, data)
        else:
            src_gateway_ip, src_gateway_mac = self._auto_assign_gateway(src_ip)
            self._send_packet_gateway(datapath, in_port, src_gateway_mac, data)

    # Host learning and flow installation
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
            
            self._log_to_blockchain("HOST_LEARNED", {
                "ip": src_ip, "mac": src_mac, "dpid": dpid, "port": port, "gateway": gw_ip
            })
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

    def _install_secure_cross_subnet_flow(self, src_ip, dst_ip):
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

        self._log_to_blockchain("SECURE_PATH_ESTABLISHED", {
            "src_ip": src_ip, "dst_ip": dst_ip, "path": path, "security_level": "HIGH"
        })

        self._create_secure_flow_context(src_ip, dst_ip, path)

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

        self.flow_paths[(src_ip, dst_ip)] = path
        self.logger.info("🔒 Installed SECURE path for %s -> %s : %s", src_ip, dst_ip, path)

    # Monitoring and congestion detection
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

    def _evaluate_congestion_for_link(self, u, v, entry):
        now = time.time()
        util = entry.get("utilization", 0.0)
        was_congested = entry.get("congested", False)
        pending_since = entry.get("pending_since", None)

        if not was_congested and util >= self.CONGESTION_THRESHOLD:
            if pending_since is None:
                entry["pending_since"] = now
            elif now - pending_since >= self.STABLE_PERIOD:
                entry["congested"] = True
                entry["pending_since"] = None
                self.avoided_edges.add((u, v))
                util_pct = int(util * 100)
                self._on_congestion_detected(u, v, util_pct)
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

    def _on_congestion_detected(self, u, v, util_pct):
        self.logger.warning("⚠️ Congestion detected on path s{}–s{} ({}%) → rerouting".format(u, v, util_pct))
        self._log_congestion_to_blockchain(f"s{u}-s{v}", util_pct, "rerouting")
        self._reinstall_all_flows_avoiding((u, v))

    def _on_congestion_cleared(self, u, v, util_pct):
        self.logger.info("✅ Congestion cleared on path s{}–s{} ({}%)".format(u, v, util_pct))
        self._log_congestion_to_blockchain(f"s{u}-s{v}", util_pct, "reverting_to_normal")
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
                    self._install_secure_cross_subnet_flow(src_ip, dst_ip)
                except Exception as e:
                    self.logger.debug("Failed reinstalling flow %s->%s: %s", src_ip, dst_ip, e)

    # Path finding
    def _edge_weight(self, u, v):
        stats = self.link_stats.get((u, v), {})
        rate = stats.get("rate_bps", 0.0)
        capacity = self.DEFAULT_LINK_CAPACITY_BPS
        util = 0.0
        if capacity > 0:
            util = min(1.0, rate / float(capacity))
        if util >= 0.95:
            return 1000.0
        return 1.0 + 9.0 * util

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

    # Helper methods
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

    def _send_packet_direct(self, datapath, in_port, dst_mac, out_port, data):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _send_packet_routed(self, datapath, in_port, gw_mac, dst_mac, out_port, data):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        actions = [parser.OFPActionSetField(eth_src=gw_mac),
                   parser.OFPActionSetField(eth_dst=dst_mac),
                   parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _send_packet_gateway(self, datapath, in_port, gw_mac, data):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        actions = [parser.OFPActionSetField(eth_src=gw_mac),
                   parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

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

    def _flood_packet(self, datapath, in_port, data):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)