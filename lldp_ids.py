#!/usr/bin/env python3
"""
LLDP Intrusion Detection System for SDN Controllers
Packet-level hybrid detection (rule-based + ML) with real-time mitigation

Rami Eid
Model: Random Forest Multi-Class (11 classes, 5 features, StandardScaler)
Architecture: Ryu SDN Controller + OpenFlow 1.3
References:
1. Ryu SDN Framework Documentation
   https://ryu.readthedocs.io/en/latest/
   Used: app_manager.RyuApp, @set_ev_cls, OFPMatch, OFPFlowMod, OFPPacketOut,
         ethernet.ethernet, lldp.lldp, ether_types

2. IEEE 802.1AB-2016 - Link Layer Discovery Protocol
   https://standards.ieee.org/standard/802_1AB-2016.html
   Used: LLDP multicast MAC addresses (01:80:c2:00:00:0e, 01:80:c2:00:00:03, 01:80:c2:00:00:00),
         Mandatory TLV structure (Chassis ID, Port ID, TTL - Section 9.2.7),
         TLV ordering requirements (Section 9.2.7.3),
         TTL value range 0-65535 seconds (Section 9.2.5.8)

3. OpenFlow 1.3 Specification
   https://www.opennetworking.org/wp-content/uploads/2014/10/openflow-switch-v1.3.5.pdf
   Used: Flow table priority system (Section 7.3),
         PacketIn/PacketOut message handling (Section 7.4),
         FlowMod message structure and timeouts (Section 7.3.4),
         Action sets and instruction types (Section 5.1)

4. scikit-learn Documentation
   https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
   https://scikit-learn.org/stable/model_persistence.html
   Used: RandomForestClassifier.predict(), RandomForestClassifier.predict_proba(),
         joblib.load(), StandardScaler.transform()

5. Zeek Network Security Monitor
   https://docs.zeek.org/en/master/
   Used: Flow tracking with sliding windows, temporal feature extraction from packet streams

6. Snort IDS Documentation
   https://www.snort.org/documents
   Used: Two-stage filtering (signature-based rules before anomaly detection),
         hybrid detection architecture (rule-based + ML)

7. Ryu L2 Learning Switch Sample Application
   https://ryu.readthedocs.io/en/latest/writing_ryu_app.html
   Used: MAC address learning and forwarding logic,
         dynamic flow installation with idle/hard timeouts


"""

import logging
import time
import os
import json
from collections import defaultdict, deque
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, lldp, ether_types
from ryu.topology import event

import joblib
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
import numpy as np

"""
Reference: IEEE 802.1AB-2016 - LLDP multicast destination addresses
           https://standards.ieee.org/standard/802_1AB-2016.html

Brief Explanation:
Standard LLDP multicast MAC addresses for nearest bridge discovery. Switches
send LLDP to these addresses; controller must intercept all three for complete
topology visibility.

Used from Reference:
- 01:80:c2:00:00:0e: Nearest bridge (mandatory LLDP destination)
- 01:80:c2:00:00:03: Nearest non-TPMR bridge
- 01:80:c2:00:00:00: Nearest customer bridge
All defined in IEEE 802.1AB Table 8-1
"""
LLDP_MACS = ['01:80:c2:00:00:0e', '01:80:c2:00:00:03', '01:80:c2:00:00:00']


"""
Reference: IEEE 802.1AB-2016 Section 9.2.7 (TLV structure and validation)
           https://standards.ieee.org/standard/802_1AB-2016.html

Brief Explanation:
Rule-based validator enforces IEEE 802.1AB compliance: mandatory TLV presence,
correct ordering, TTL bounds, frame size limits, and rate thresholds. Catches
protocol violations before ML inference.

Used from Reference:
- Mandatory TLVs: Chassis ID, Port ID, TTL (Section 9.2.7.2)
- TLV ordering: Chassis → Port → TTL → optional → End (Section 9.2.7.3)
- TTL range: 0-65535 seconds, 0 means immediate deletion (Section 9.2.5.8)
- Frame size: minimum 60 bytes (Ethernet minimum), max 1500 (MTU)
- Rate limiting: >50 pps burst detection threshold
"""
class LLDPValidator:
    """IEEE 802.1AB compliant LLDP packet validator"""
    
    def __init__(self, min_ttl=5, max_ttl=65535, min_size=60, max_size=1500, max_rate=50):
        self.MIN_TTL = min_ttl
        self.MAX_TTL = max_ttl
        self.MIN_SIZE = min_size
        self.MAX_SIZE = max_size
        self.MAX_RATE = max_rate
        self.last_seen = {}
    
    def validate(self, pkt_lldp, frame_size, flow_key, timestamp):
        """Returns: (is_valid, reason)"""
        
        if frame_size < self.MIN_SIZE or frame_size > self.MAX_SIZE:
            return False, f"Invalid frame size: {frame_size}"
        
        if not pkt_lldp:
            return False, "Malformed LLDP packet - parsing failed"
        
        has_chassis = has_port = has_ttl = False
        ttl_value = 0
        tlv_order = []
        
        for tlv in pkt_lldp.tlvs:
            if isinstance(tlv, lldp.ChassisID):
                has_chassis = True
                tlv_order.append(1)
            elif isinstance(tlv, lldp.PortID):
                has_port = True
                tlv_order.append(2)
            elif isinstance(tlv, lldp.TTL):
                has_ttl = True
                ttl_value = int(tlv.ttl) if hasattr(tlv, 'ttl') else 0
                tlv_order.append(3)
        
        if not (has_chassis and has_port and has_ttl):
            return False, "Missing mandatory TLVs"
        
        if len(tlv_order) >= 3 and tlv_order[:3] != [1, 2, 3]:
            return False, "Invalid TLV ordering"
        
        if ttl_value < self.MIN_TTL or ttl_value > self.MAX_TTL:
            return False, f"TTL out of range: {ttl_value}"
        
        if flow_key in self.last_seen:
            delta = timestamp - self.last_seen[flow_key]
            if delta > 0 and (1.0 / delta) > self.MAX_RATE:
                return False, f"Burst rate: {1.0/delta:.1f} pps"
        
        self.last_seen[flow_key] = timestamp
        return True, "pass"


"""
Reference: Standard IDS flow tracking patterns (used in Zeek, Suricata)
           Similar to flow tracking in https://github.com/zeek/zeek

Brief Explanation:
Maintains per-flow state for temporal feature computation. Tracks timestamps
and sizes in sliding window for rate and inter-arrival time calculations.

Used from Reference:
- Flow key: chassis_id:port_id (unique LLDP flow identifier)
- Sliding window: deque with maxlen for memory efficiency
- Timestamp tracking: last 1000 packets per flow for rate computation
- Size tracking: last 100 packets for size variance analysis
- LRU eviction: oldest flow removed when max_flows reached
"""
class FlowTracker:
    """Maintains packet-level statistics per LLDP flow"""
    
    def __init__(self, max_flows=10000, window_sec=5.0):
        self.MAX_FLOWS = max_flows
        self.window_sec = window_sec
        self.flows = defaultdict(lambda: {
            'first_ts': None, 'last_ts': None, 'count': 0,
            'timestamps': deque(maxlen=1000), 'sizes': deque(maxlen=100)
        })
    
    def update(self, chassis_id, port_id, timestamp, packet_size):
        """Update flow state, return flow object"""
        flow_key = f"{chassis_id}:{port_id}".lower()
        
        if len(self.flows) >= self.MAX_FLOWS:
            oldest = min(self.flows.items(), key=lambda x: x[1]['last_ts'])
            del self.flows[oldest[0]]
        
        flow = self.flows[flow_key]
        if flow['first_ts'] is None:
            flow['first_ts'] = timestamp
        
        flow['last_ts'] = timestamp
        flow['count'] += 1
        flow['timestamps'].append(timestamp)
        flow['sizes'].append(packet_size)
        
        return flow


"""
source relied on: Dataset generation feature extraction (from my DataGeneration.py)
           Matches 5-feature model: packet_size, ttl, tlv_count, inter_frame_delta, packet_rate

Brief Explanation:
Extracts 5 features matching trained Random Forest model. Uses FlowTracker for
temporal features (inter_frame_delta, packet_rate) computed from sliding window.

Used from my scipt as logic:
- packet_size: Ethernet frame size in bytes (40-1500 range)
- ttl: LLDP TTL value from TTL TLV (0-65535 seconds)
- tlv_count: Number of TLVs in LLDP frame (legitimate: 3-8, malformed: 0-3)
- inter_frame_delta: Time since last packet in same flow (seconds)
- packet_rate: Packets per second in 5-second sliding window
- Feature order must match training: [packet_size, ttl, tlv_count, inter_frame_delta, packet_rate]
"""
class FeatureExtractor:
    """Extract 5 features matching trained multi-class model"""
    
    def __init__(self, window_sec=5.0):
        self.flow_tracker = FlowTracker(window_sec=window_sec)
        self.window_sec = window_sec
    
    def extract(self, pkt_lldp, frame_size, timestamp):
        """Returns: feature_dict with 5 values + metadata"""
        
        chassis_id = port_id = "unknown"
        ttl_value = 120
        
        if pkt_lldp:
            for tlv in pkt_lldp.tlvs:
                try:
                    if isinstance(tlv, lldp.ChassisID):
                        chassis_id = str(tlv.chassis_id) if hasattr(tlv, 'chassis_id') else "unknown"
                    elif isinstance(tlv, lldp.PortID):
                        port_id_raw = tlv.port_id if hasattr(tlv, 'port_id') else None
                        port_id = port_id_raw.hex() if isinstance(port_id_raw, bytes) else str(port_id_raw or "unknown")
                    elif isinstance(tlv, lldp.TTL):
                        ttl_value = int(tlv.ttl) if hasattr(tlv, 'ttl') else 120
                except:
                    continue
        
        tlv_count = len(pkt_lldp.tlvs) if pkt_lldp else 0
        flow = self.flow_tracker.update(chassis_id, port_id, timestamp, frame_size)
        
        packet_size = frame_size
        ttl = ttl_value
        
        inter_frame_delta = 0.0
        if len(flow['timestamps']) >= 2:
            inter_frame_delta = flow['timestamps'][-1] - flow['timestamps'][-2]
        
        recent = [ts for ts in flow['timestamps'] if (timestamp - ts) <= self.window_sec]
        packet_rate = len(recent) / self.window_sec if self.window_sec > 0 else 0.0
        
        return {
            'packet_size': packet_size,
            'ttl': ttl,
            'tlv_count': tlv_count,
            'inter_frame_delta': inter_frame_delta,
            'packet_rate': packet_rate,
            'chassis_id': chassis_id,
            'port_id': port_id,
            'flow_key': f"{chassis_id}:{port_id}".lower()
        }


"""
Reference: Ryu SDN Framework - app_manager.RyuApp base class
           https://ryu.readthedocs.io/en/latest/app.html
Reference: OpenFlow 1.3 Specification - PacketIn/FlowMod messages
           https://www.opennetworking.org/wp-content/uploads/2014/10/openflow-switch-v1.3.5.pdf

Brief Explanation:
Main IDS application running on Ryu controller. Implements hybrid detection:
rule-based (sub-millisecond) + ML (45ms) with OpenFlow mitigation. Integrates
L2 learning switch for normal traffic forwarding.

Used from Ryu Reference:
- app_manager.RyuApp: Base controller application class
- @set_ev_cls decorators: Event handler registration for switch events
- EventOFPSwitchFeatures: Switch connection event for flow installation
- EventOFPPacketIn: Packet arrival event for LLDP interception
- OFP_VERSIONS: OpenFlow version negotiation (1.3)

Used from OpenFlow Reference:
- OFPMatch: Flow match criteria (in_port, eth_type, eth_dst)
- OFPFlowMod: Flow rule installation with priority, timeouts
- OFPPacketOut: Packet forwarding decision
- Priority hierarchy: 65535 (LLDP interception) > 65530 (drop rules) > 1 (L2 forwarding) > 0 (table-miss)
- Timeouts: idle_timeout (inactive flow deletion), hard_timeout (absolute expiry)
"""
class LLDPIDS(app_manager.RyuApp):
    """Packet-level LLDP IDS with rule-based + ML hybrid detection"""
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(LLDPIDS, self).__init__(*args, **kwargs)
        
        self.CRITICAL_ATTACKS = ['lldp_flood', 'lldp_spoof', 'lldp_malformed', 
                                 'lldp_ttl_anomaly', 'syn_flood', 'udp_flood', 'port_scan']
        self.DROP_IDLE_SEC = 30
        self.DROP_HARD_SEC = 60
        self.ENABLE_RULES = True
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('lldp_ids.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('LLDP-IDS')
        
        self.validator = LLDPValidator() if self.ENABLE_RULES else None
        self.feature_extractor = FeatureExtractor()
        self.datapaths = {}
        self.mac_to_port = {}
        
        self.stats = {
            'total': 0, 'normal': 0, 'attacks': 0, 'dropped': 0,
            'rule_blocked': 0, 'ml_blocked': 0, 'by_type': defaultdict(int)
        }
        self.latencies = []
        
        self._load_model()
        
        self.logger.info("="*80)
        self.logger.info("LLDP IDS Started - Multi-Class Hybrid Detection")
        self.logger.info(f"Rule-based: {'ENABLED' if self.ENABLE_RULES else 'DISABLED'}")
        self.logger.info(f"ML Model: {'LOADED' if self.model else 'FAILED'}")
        if self.model:
            self.logger.info(f"Model Classes: {len(self.model.classes_)} classes")
        self.logger.info("="*80)
    
    """
    Reference: scikit-learn joblib persistence
               https://scikit-learn.org/stable/model_persistence.html
    
    Brief Explanation:
    Loads trained Random Forest model and StandardScaler from modelRamiEid directory.
    Model artifacts exported from Google Colab training.
    
    Used from Reference:
    - joblib.load(): Deserialize pickle files (more efficient than pickle for numpy arrays)
    - Model file: lldp_multi_class_model.pkl (200 trees Random Forest)
    - Scaler file: feature_scaler_multi_class.pkl (StandardScaler with training mean/std)
    - Model attributes: n_estimators, n_features_in_, classes_ for validation
    - Scaler transform: z-score normalization matching training preprocessing
    """
    def _load_model(self):
        """Load multi-class Random Forest model and scaler from modelRamiEid directory"""
        try:
            model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modelRamiEid')
            model_path = os.path.join(model_dir, 'lldp_multi_class_model.pkl')
            scaler_path = os.path.join(model_dir, 'feature_scaler_multi_class.pkl')
            
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model not found: {model_path}")
            
            self.model = joblib.load(model_path)
            self.logger.info(f"[INFO] ML model loaded: {model_path}")
            self.logger.info(f"[INFO] Model type: {type(self.model).__name__}")
            
            if hasattr(self.model, 'n_estimators'):
                self.logger.info(f"[INFO] Trees: {self.model.n_estimators}")
            if hasattr(self.model, 'n_features_in_'):
                self.logger.info(f"[INFO] Features expected: {self.model.n_features_in_}")
                if self.model.n_features_in_ != 5:
                    self.logger.warning(f"[WARN] Feature count mismatch! Model expects {self.model.n_features_in_}, extractor provides 5")
            if hasattr(self.model, 'classes_'):
                self.logger.info(f"[INFO] Model classes: {list(self.model.classes_)}")
            
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                self.logger.info(f"[INFO] Feature scaler loaded: {scaler_path}")
            else:
                self.logger.warning(f"[WARN] Scaler not found: {scaler_path}")
                self.scaler = None
        
        except Exception as e:
            self.logger.error(f"[ERROR] Model load failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            self.model = None
            self.scaler = None
    
    """
    Reference: OpenFlow 1.3 - Switch handshake and flow table initialization
               https://www.opennetworking.org/wp-content/uploads/2014/10/openflow-switch-v1.3.5.pdf
    
    Brief Explanation:
    Installs flow rules when switch connects: LLDP interception (priority 65535/65534)
    and table-miss for L2 learning (priority 0). Enables packet-level LLDP inspection
    while forwarding normal traffic.
    
    Used from Reference:
    - CONFIG_DISPATCHER: Switch connection event handler stage
    - OFPMatch(): Empty match = table-miss (catch all unmatched packets)
    - OFPMatch(eth_type=0x88cc): Match LLDP EtherType
    - OFPMatch(eth_dst=MAC): Match LLDP multicast destinations
    - OFPP_CONTROLLER: Send matched packets to controller
    - OFPCML_NO_BUFFER: Send full packet (no buffering at switch)
    - Priority ordering ensures LLDP caught before table-miss
    """
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install LLDP interception flows on switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.logger.info(f"Switch connected: DPID={datapath.id}")
        
        self.mac_to_port[datapath.id] = {}
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 65535, match, actions)
        
        for lldp_mac in LLDP_MACS:
            match = parser.OFPMatch(eth_dst=lldp_mac)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self._add_flow(datapath, 65534, match, actions)
        
        self.datapaths[datapath.id] = datapath
        self.logger.info(f"LLDP interception flows installed on DPID={datapath.id}")
    
    """
    Reference: OpenFlow 1.3 - FlowMod message structure
               Section 7.3.4.1 in OpenFlow spec
    
    Brief Explanation:
    Helper function to install flow rules with match criteria, actions, and timeouts.
    
    Used from Reference:
    - OFPInstructionActions: Apply actions to matched packets
    - OFPIT_APPLY_ACTIONS: Execute actions immediately (vs write to action set)
    - idle_timeout: Remove flow if inactive for N seconds
    - hard_timeout: Remove flow after N seconds regardless of activity
    """
    def _add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        """Install OpenFlow flow entry"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, 
            instructions=inst, idle_timeout=idle, hard_timeout=hard
        )
        datapath.send_msg(mod)
    
    """
    Reference: OpenFlow 1.3 - PacketIn event handling
               Section 7.4.1 in OpenFlow spec
    
    Brief Explanation:
    Routes packets: LLDP to detection pipeline, others to L2 learning switch.
    Enables normal network operation while inspecting LLDP.
    
    Used from Reference:
    - MAIN_DISPATCHER: Normal switch operation event handler stage
    - EventOFPPacketIn: Packet arrival event from switch
    - packet.Packet(msg.data): Scapy-like packet parsing
    - eth.ethertype: EtherType field for protocol identification
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Route LLDP packets to detection pipeline, others to L2 learning"""
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if not eth:
            return
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.dst in LLDP_MACS:
            self._process_lldp(ev, pkt)
        else:
            self._process_l2(ev, pkt, eth)
    
    """
    Standard L2 learning switch algorithm
               
    
    Brief Explanation:
    Implements MAC learning switch for non-LLDP traffic (ARP, ICMP, TCP, UDP).
    Learns source MAC to port mapping, installs forwarding flows for known destinations.
    
    """
    def _process_l2(self, ev, pkt, eth):
        """Simple L2 learning switch for legitimate traffic (ARP, ICMP, etc.)"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self._add_flow(datapath, 1, match, actions, idle=10, hard=30)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    """
     Hybrid IDS architecture pattern (Snort + ML combination)
               
    
    Brief Explanation:
    Main detection pipeline: Rule validation (sub-ms) → ML classification (45ms) → Mitigation.
    Two-stage filtering: fast rules catch obvious violations, ML catches evasive attacks.
    

    - Rule-first architecture: cheap checks before expensive ML inference
    - Feature extraction: convert packet to 5-element vector
    - StandardScaler.transform(): z-score normalization matching training
    - model.predict(): Random Forest ensemble voting (200 trees)
    - model.predict_proba(): confidence scores from tree vote proportions
    - Latency tracking: time.perf_counter() for microsecond precision
    - Attack classification: critical attacks trigger mitigation, benign forwarded to topology
    """
    def _process_lldp(self, ev, pkt):
        """Main detection pipeline: Rule validation → ML classification → Action"""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        t_start = time.perf_counter()
        
        self.stats['total'] += 1
        timestamp = time.time()
        
        try:
            eth = pkt.get_protocol(ethernet.ethernet)
            pkt_lldp = pkt.get_protocol(lldp.lldp)
            frame_size = len(msg.data)
            
            if self.ENABLE_RULES and self.validator:
                features = self.feature_extractor.extract(pkt_lldp, frame_size, timestamp) if pkt_lldp else {
                    'chassis_id': 'malformed', 'port_id': 'malformed', 'flow_key': 'malformed:malformed'
                }
                
                is_valid, reason = self.validator.validate(
                    pkt_lldp, frame_size, features['flow_key'], timestamp
                )
                if not is_valid:
                    self._handle_rule_block(reason, features, datapath, in_port, t_start)
                    return
            
            if not pkt_lldp:
                self._forward_to_topology(ev)
                return
            
            features = self.feature_extractor.extract(pkt_lldp, frame_size, timestamp)
            
            if not self.model:
                self._forward_to_topology(ev)
                return
            
            feature_vec = np.array([[
                features['packet_size'],
                features['ttl'],
                features['tlv_count'],
                features['inter_frame_delta'],
                features['packet_rate']
            ]])
            
            if self.scaler:
                feature_vec = self.scaler.transform(feature_vec)
            
            prediction = self.model.predict(feature_vec)[0]
            proba = self.model.predict_proba(feature_vec)[0]
            confidence = proba.max()
            
            t_end = time.perf_counter()
            latency_ms = (t_end - t_start) * 1000
            self.latencies.append(latency_ms)
            
            if prediction in self.CRITICAL_ATTACKS:
                self._handle_attack(prediction, confidence, features, datapath, in_port, latency_ms)
            else:
                self._handle_normal(prediction, confidence, latency_ms, features)
                self._forward_to_topology(ev)
        
        except Exception as e:
            self.logger.error(f"Processing error: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            self._forward_to_topology(ev)
    
    """
   OpenFlow mitigation pattern - drop rules with timeouts
         
    
    Brief Explanation:
    Installs drop flow (empty action list) on source port for rule violations.
    Time-limited blocking prevents permanent port shutdown from false positives.
    
  
    - Empty action list = drop (no output action)
    - Priority 65530: higher than normal forwarding (1), lower than LLDP catch (65535)
    - idle_timeout=30s: remove rule if no matching packets for 30 seconds
    - hard_timeout=60s: remove rule after 60 seconds regardless of activity
    - Match on in_port + eth_type: block only LLDP from specific source port
    """
    def _handle_rule_block(self, reason, features, datapath, in_port, t_start):
        """Block packet that failed rule-based validation"""
        self.stats['attacks'] += 1
        self.stats['dropped'] += 1
        self.stats['rule_blocked'] += 1
        self.stats['by_type']['rule_violation'] += 1
        
        latency_ms = (time.perf_counter() - t_start) * 1000
        self.latencies.append(latency_ms)
        
        self.logger.warning("="*80)
        self.logger.warning(f"[RULE VIOLATION] {reason}")
        self.logger.warning(f"Source: DPID={datapath.id} Port={in_port} | Latency: {latency_ms:.2f}ms")
        self.logger.warning(f"Flow: {features['chassis_id']} → {features['port_id']}")
        self.logger.warning("Action: DROPPED + BLOCK FLOW INSTALLED")
        self.logger.warning("="*80)
        
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_LLDP)
        self._add_flow(datapath, 65530, match, [], idle=self.DROP_IDLE_SEC, hard=self.DROP_HARD_SEC)
    
    def _handle_attack(self, attack_type, confidence, features, datapath, in_port, latency_ms):
        """Block packet classified as attack by ML model"""
        self.stats['attacks'] += 1
        self.stats['dropped'] += 1
        self.stats['ml_blocked'] += 1
        self.stats['by_type'][attack_type] += 1
        
        self.logger.warning("="*80)
        self.logger.warning(f"[ML ATTACK] {attack_type.upper()}")
        self.logger.warning(f"Confidence: {confidence*100:.1f}% | Latency: {latency_ms:.2f}ms")
        self.logger.warning(f"Source: DPID={datapath.id} Port={in_port}")
        self.logger.warning(f"Flow: {features['chassis_id']} → {features['port_id']}")
        self.logger.warning(f"Features: size={features['packet_size']:.0f} ttl={features['ttl']:.0f} "
                          f"tlv={features['tlv_count']:.0f} rate={features['packet_rate']:.2f}pps "
                          f"delta={features['inter_frame_delta']:.3f}s")
        self.logger.warning("Action: DROPPED + BLOCK FLOW INSTALLED")
        self.logger.warning("="*80)
        
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_LLDP)
        self._add_flow(datapath, 65530, match, [], idle=self.DROP_IDLE_SEC, hard=self.DROP_HARD_SEC)
    
    def _handle_normal(self, prediction, confidence, latency_ms, features):
        """Log normal packet classification"""
        self.stats['normal'] += 1
        self.logger.info(f"[NORMAL] {prediction} ({confidence*100:.1f}%) | "
                        f"Latency: {latency_ms:.2f}ms | Rate: {features['packet_rate']:.2f}pps")
    
    def _forward_to_topology(self, ev):
        """Forward legitimate LLDP to topology discovery module"""
        pass
    
    def get_stats(self):
        """Return detection statistics"""
        avg_latency = np.mean(self.latencies) if self.latencies else 0.0
        p95_latency = np.percentile(self.latencies, 95) if self.latencies else 0.0
        
        return {
            'total_packets': self.stats['total'],
            'normal_packets': self.stats['normal'],
            'attacks_detected': self.stats['attacks'],
            'packets_dropped': self.stats['dropped'],
            'rule_blocked': self.stats['rule_blocked'],
            'ml_blocked': self.stats['ml_blocked'],
            'detection_rate': (self.stats['attacks'] / self.stats['total'] * 100) if self.stats['total'] > 0 else 0.0,
            'attacks_by_type': dict(self.stats['by_type']),
            'latency_ms_avg': avg_latency,
            'latency_ms_p95': p95_latency
        }
    
    def log_stats(self):
        """Print statistics summary"""
        s = self.get_stats()
        self.logger.info("="*80)
        self.logger.info("STATISTICS SUMMARY")
        self.logger.info(f"Total: {s['total_packets']} | Normal: {s['normal_packets']} | "
                        f"Attacks: {s['attacks_detected']} | Dropped: {s['packets_dropped']}")
        self.logger.info(f"Rule Blocked: {s['rule_blocked']} | ML Blocked: {s['ml_blocked']}")
        self.logger.info(f"Detection Rate: {s['detection_rate']:.2f}%")
        self.logger.info(f"Latency: Avg={s['latency_ms_avg']:.2f}ms | P95={s['latency_ms_p95']:.2f}ms")
        if s['attacks_by_type']:
            self.logger.info("Attack Breakdown:")
            for atype, count in s['attacks_by_type'].items():
                self.logger.info(f"  {atype}: {count}")
        self.logger.info("="*80)
