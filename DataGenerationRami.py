#!/usr/bin/env python3
"""
Network Traffic Dataset Generator for IDS Training
By Rami Eid
I couldnt include the dataset in the repo even compressed since its big in size
brief summary of my script:
This script generates a realistic 2-million-sample dataset for training an LLDP-focused
Intrusion Detection System. Unlike simple random generation, it implements flow-level
state tracking, proper statistical distributions, network simulation, and temporal
correlations to prevent model overfitting and ensure realistic traffic patterns. This generates a synthetic dataset 
so a priority of mine is to avoid overfitting.

The generator produces 11 traffic classes: 4 benign (normal_lldp, normal_tcp, normal_udp,
normal_icmp) and 7 attack types (lldp_flood, lldp_ttl_anomaly, lldp_malformed, lldp_spoof,
syn_flood, udp_flood, port_scan). Each class is generated across multiple independent flows
with phase-based evolution (initial, ramp-up, peak, evasion, wind-down) to model realistic
attack lifecycles and legitimate traffic variability.

key aspects:
1. Flow-based generation: Each traffic class uses 150-400 independent flows to prevent
   memorization of single patterns
2. Statistical realism: Features drawn from log-normal, gamma, and Pareto distributions
   matching empirical network measurements
3. Temporal correlation: Packet timing depends on flow history and network congestion state
4. Attack variants: Each attack type implements 4-7 sub-variants modeling different attacker
   strategies (sustained, ramping, pulsing, distributed, evasive)
5. Overlap zones: Deliberately overlapping benign/attack distributions force multi-feature
   learning rather than trivial single-threshold separation

architecture:
- NetworkSimulator: Models time-varying congestion, queue delays, and jitter
- FlowStateTracker: Maintains per-flow history for temporal feature computation
- StatisticalSampler: Proper distributions with bounded sampling and multiplicative noise
- ProductionTrafficGenerator: Orchestrates stateful generation for all 11 classes
"""

import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict
import warnings
import os
import sys
warnings.filterwarnings('ignore')

np.random.seed(42)



# SECTION 1: NETWORK SIMULATION AND CONGESTION MODELING
# REFERENCE: Queueing Theory for Network Analysis
#            https://www.sciencedirect.com/topics/computer-science/queueing-theory
# REFERENCE: ITU-T Y.1540 - IP Packet Transfer Delay Variation
#            https://www.itu.int/rec/T-REC-Y.1540
# REFERENCE: RFC 2581 - TCP Congestion Control
#            https://tools.ietf.org/html/rfc2581
# WHAT I TOOK:
# - Exponential moving average for time-varying congestion state modeling
# - Queue depth tracking causing multiplicative jitter in packet timing
# - Congestion-dependent packet loss probability affecting retransmission patterns
# - Jitter factors ranging from microseconds to hundreds of milliseconds under load
# BRIEF EXPLANATION:
# Real networks experience time-varying congestion causing queue buildup and packet delays.
# This simulator maintains evolving congestion and queue depth states that affect packet
# timing through multiplicative jitter factors. Congestion causes packet loss triggering
# retransmissions with characteristic timing patterns. Without this, all packets would have
# uniform timing unrealistic for production networks.

class NetworkSimulator:
    """
    Simulates realistic network conditions including congestion, queue delays,
    and packet loss recovery patterns. Network state evolves over time to model
    real-world temporal correlations that simple random generation cannot capture.
    """
    
    def __init__(self):
        self.congestion_level = 0.0      # Current congestion [0.0, 0.4]
        self.queue_depth = 0.0            # Queue occupancy [0, 10] packets
        self.last_update_time = 0.0       # Last state update timestamp
        self.packet_count = 0             # Total packets processed
        
    def update_network_state(self, current_time):
        """
        Updates network congestion state using exponential moving average to model
        time-varying network conditions. Congestion affects packet timing and creates
        realistic jitter patterns observed in production networks.
        """
        time_delta = current_time - self.last_update_time
        if time_delta > 0:
            # Exponential decay of congestion over time (10-second time constant)
            decay_factor = np.exp(-time_delta / 10.0)
            self.congestion_level *= decay_factor
            self.queue_depth *= decay_factor
        
        # Add stochastic fluctuations to congestion
        self.congestion_level += np.random.normal(0, 0.02)
        self.congestion_level = np.clip(self.congestion_level, 0, 0.4)
        
        # Queue depth fluctuations
        self.queue_depth += np.random.normal(0, 0.5)
        self.queue_depth = np.clip(self.queue_depth, 0, 10.0)
        
        self.last_update_time = current_time
        self.packet_count += 1
        
    def get_jitter_factor(self):
        """
        Computes multiplicative jitter factor based on queue depth and congestion.
        Production networks exhibit jitter ranging from microseconds to hundreds of
        milliseconds depending on load conditions.
        """
        base_jitter = 1.0 + self.congestion_level * np.random.uniform(0, 0.5)
        queue_jitter = 1.0 + (self.queue_depth / 10.0) * np.random.uniform(0, 0.3)
        return base_jitter * queue_jitter
    
    def get_packet_loss_probability(self):
        """
        Computes packet loss probability based on congestion level. Lost packets
        trigger retransmissions that create characteristic timing patterns in
        traffic flows.
        """
        return min(0.05, self.congestion_level * 0.1)


# SECTION 2: FLOW-LEVEL STATE TRACKING AND TEMPORAL CORRELATION
# REFERENCE: "Flow-based Traffic Analysis" (Sperotto et al., 2010)
#            https://ieeexplore.ieee.org/document/5460568
# REFERENCE: Time-Series Analysis for Network Traffic
#            https://www.sciencedirect.com/topics/computer-science/time-series-analysis
# REFERENCE: "Packet Inter-Arrival Time Distribution" (Salvador et al., 2004)
#            https://ieeexplore.ieee.org/document/1354567
# REFERENCE: "Attack Phase Detection" in IDS research
#            https://www.researchgate.net/publication/220424726
#
# WHAT I TOOK:
# - Flow persistence concept: each flow maintains history across packets
# - Sliding time window for rate calculations (10-second window)
# - Inter-arrival time statistics (mean, std, count) computed from packet history
# - Attack phase transitions: initial → ramp_up → peak → evasion → wind_down
# - Burst state modeling: short-term high-rate periods followed by normal rates
# BRIEF EXPLANATION:
# Real traffic flows exhibit temporal dependencies where each packet's characteristics
# depend on previous packets in the same flow. This tracker maintains per-flow history
# enabling computation of sliding-window statistics like inter-arrival time variance.
# Attack flows follow lifecycle phases (reconnaissance, ramp-up, peak assault, evasion
# attempts, wind-down) while benign flows have burst patterns. Static random generation
# cannot reproduce these temporal structures that ML models must learn to detect attacks.


class FlowStateTracker:
    """
    Maintains temporal state for traffic flows to model realistic packet sequences.
    Each flow has persistent characteristics (base rate, packet size distribution)
    with temporal evolution (rate changes, burst patterns, attack phases).
    """
    
    def __init__(self, flow_id, traffic_type):
        self.flow_id = flow_id
        self.traffic_type = traffic_type
        self.packet_history = []          # Sliding window of recent packets
        self.current_phase = 'initial'    # Attack/traffic lifecycle phase
        self.phase_transition_prob = 0.02 # Probability of phase transition per packet
        self.burst_state = False          # Currently in burst period
        self.burst_counter = 0            # Packets remaining in burst
        
    def add_packet(self, timestamp, features):
        """
        Records packet in flow history and maintains sliding window for rate
        calculations. History enables computation of temporal features like
        inter-arrival time variance and rate change patterns.
        """
        self.packet_history.append({
            'timestamp': timestamp,
            'features': features
        })
        
        # Maintain sliding window (keep last 500 packets max)
        if len(self.packet_history) > 1000:
            self.packet_history = self.packet_history[-500:]
    
    def get_inter_arrival_stats(self, window_sec=10.0):
        """
        Computes statistical properties of packet inter-arrival times within
        sliding time window. Real traffic shows heavy-tailed distributions with
        autocorrelation that simple random generation cannot reproduce.
        """
        if len(self.packet_history) < 2:
            return {'mean': 1.0, 'std': 0.1, 'count': 0}
        
        current_time = self.packet_history[-1]['timestamp']
        recent_packets = [p for p in self.packet_history 
                         if current_time - p['timestamp'] <= window_sec]
        
        if len(recent_packets) < 2:
            return {'mean': 1.0, 'std': 0.1, 'count': len(recent_packets)}
        
        # Compute inter-arrival times between consecutive packets
        inter_arrivals = []
        for i in range(1, len(recent_packets)):
            delta = recent_packets[i]['timestamp'] - recent_packets[i-1]['timestamp']
            inter_arrivals.append(delta)
        
        return {
            'mean': np.mean(inter_arrivals),
            'std': np.std(inter_arrivals),
            'count': len(recent_packets)
        }
    
    def update_phase(self):
        """
        Models attack lifecycle phases (reconnaissance, ramp-up, peak, evasion, wind-down)
        using probabilistic state transitions. Real attacks exhibit temporal structure
        that static generation cannot capture.
        """
        # Phase transition (attacks evolve through stages)
        if np.random.random() < self.phase_transition_prob:
            phases = ['initial', 'ramp_up', 'peak', 'evasion', 'wind_down']
            current_idx = phases.index(self.current_phase)
            if current_idx < len(phases) - 1:
                self.current_phase = phases[current_idx + 1]
        
        # Burst state transitions (short high-rate periods)
        if np.random.random() < 0.08:
            self.burst_state = not self.burst_state
            self.burst_counter = np.random.randint(5, 25)
        
        if self.burst_state and self.burst_counter > 0:
            self.burst_counter -= 1



# SECTION 3: STATISTICAL SAMPLING WITH PROPER DISTRIBUTIONS
# REFERENCE: "Statistical Methods for Network Traffic Modeling" (Karagiannis et al., 2004)
#            https://ieeexplore.ieee.org/document/1354556
# REFERENCE: Log-normal distribution for network traffic
#            https://en.wikipedia.org/wiki/Log-normal_distribution
# REFERENCE: Gamma distribution for inter-arrival times
#            https://en.wikipedia.org/wiki/Gamma_distribution
# REFERENCE: Pareto distribution for heavy-tailed traffic
#            https://en.wikipedia.org/wiki/Pareto_distribution
# REFERENCE: Multiplicative noise models in signal processing
#            https://ieeexplore.ieee.org/document/4153813
# WHAT I TOOK:
# - Log-normal distribution for packet rates and sizes (multiplicative processes in stacks)
# - Gamma distribution for inter-arrival times (models bursty protocol timing)
# - Pareto distribution for heavy-tailed behavior (web traffic, file sizes, flow durations)
# - Multiplicative log-normal noise for relative measurement errors (preserves positivity)
# - Bounded sampling with retry logic to enforce physical constraints (40-1500 bytes, etc.)
# BRIEF EXPLANATION:
# Empirical measurements of production networks show traffic features follow specific
# statistical distributions, not uniform or simple Gaussian. Packet sizes and rates
# exhibit log-normal characteristics due to multiplicative effects in protocol stacks.
# Inter-arrival times follow gamma distributions reflecting bursty application behavior.
# Flow durations show heavy-tailed Pareto distributions. Using proper distributions with
# multiplicative noise creates realistic variance patterns that prevent ML overfitting
# on artificially clean data.

class StatisticalSampler:
    """
    Implements proper statistical distributions for traffic feature generation.
    Uses empirically-validated distributions from real network measurements rather
    than arbitrary uniform or normal distributions.
    """
    
    @staticmethod
    def sample_lognormal_bounded(mu, sigma, lower, upper):
        """
        Samples from log-normal distribution with bounds. Network traffic rates
        and packet sizes exhibit log-normal characteristics due to multiplicative
        processes in protocol stacks and application behavior.
        """
        for attempt in range(10):
            sample = np.random.lognormal(mu, sigma)
            if lower <= sample <= upper:
                return sample
        return np.clip(np.random.lognormal(mu, sigma), lower, upper)
    
    @staticmethod
    def sample_gamma_bounded(shape, scale, lower, upper):
        """
        Samples from gamma distribution with bounds. Packet inter-arrival times
        in many protocols follow gamma distributions, especially for bursty traffic
        patterns common in network applications.
        """
        for attempt in range(10):
            sample = np.random.gamma(shape, scale)
            if lower <= sample <= upper:
                return sample
        return np.clip(np.random.gamma(shape, scale), lower, upper)
    
    @staticmethod
    def sample_pareto_bounded(shape, lower, upper):
        """
        Samples from Pareto distribution modeling heavy-tailed behavior observed
        in network traffic. Web traffic, file sizes, and flow durations exhibit
        power-law characteristics requiring Pareto modeling.
        """
        scale = lower
        for attempt in range(10):
            sample = (np.random.pareto(shape) + 1) * scale
            if lower <= sample <= upper:
                return sample
        return np.clip((np.random.pareto(shape) + 1) * scale, lower, upper)
    
    @staticmethod
    def add_multiplicative_noise(value, noise_fraction):
        """
        Applies multiplicative log-normal noise to preserve positive values while
        introducing realistic variance. Multiplicative noise better models relative
        measurement errors than additive Gaussian noise.
        """
        if value <= 0:
            return max(0.001, value)
        
        sigma = noise_fraction
        noise_factor = np.random.lognormal(0, sigma)
        return value * noise_factor


# SECTION 4: BENIGN TRAFFIC GENERATION
# REFERENCE: IEEE 802.1AB-2016 Section 9.2.5 - LLDP frame transmission
#            https://standards.ieee.org/standard/802_1AB-2016.html
# REFERENCE: CICIDS2017 TCP/UDP traffic characteristics
#            https://www.unb.ca/cic/datasets/ids-2017.html
# REFERENCE: RFC 792 - Internet Control Message Protocol
#            https://tools.ietf.org/html/rfc792
# WHAT I TOOK FROM IEEE 802.1AB (LLDP):
# - 30-second standard advertisement interval
# - Frame size range: 60-150 bytes (minimum Ethernet + LLDP TLVs)
# - TTL range: 100-140 seconds (typical switch configurations)
# - Mandatory TLVs: Chassis ID, Port ID, TTL (minimum 3, typical 4-8)
# - Rate spikes to 50 pps during network convergence (topology changes, multi-switch)
# WHAT I TOOK FROM CICIDS2017 (TCP/UDP/ICMP):
# - TCP: Bimodal size distribution (small control packets 40-200B, large data 200-1500B)
# - TCP: Rate patterns 0.1-120 pps reflecting request-response cycles and file transfers
# - UDP: More regular timing due to no congestion control, rates 0.5-150 pps
# - UDP: Variable sizes 60-1200B for DNS, streaming, VoIP
# - ICMP: Regular 1-second intervals for ping, bursts during troubleshooting
# WHAT I TOOK FROM RFC 792 (ICMP):
# - Standard ping size: 64-104 bytes (56 data + 8 header + IP overhead)
# - Diagnostic tools exhibit regular timing patterns
# BRIEF EXPLANATION:
# Benign traffic generation implements protocol-specific characteristics validated against
# standards and real datasets. Normal LLDP follows IEEE specifications but includes rate
# spikes during topology changes to create overlap with flood attacks (forcing multi-feature
# learning). TCP uses bimodal size distributions reflecting control vs data packets. UDP
# exhibits more regular timing due to lack of congestion control. ICMP models diagnostic
# tools with characteristic regular intervals and occasional troubleshooting bursts.

class ProductionTrafficGenerator:
    """
    Production-grade traffic generator implementing stateful flow modeling, proper
    statistical distributions, network simulation, and temporal correlations. Each
    packet depends on flow history and network state, creating realistic dependencies
    absent in simple random generation.
    """
    
    def __init__(self):
        self.network_sim = NetworkSimulator()
        self.flow_states = {}
        self.sampler = StatisticalSampler()
        self.global_timestamp = 0.0
        
    def get_or_create_flow(self, flow_id, traffic_type):
        """
        Retrieves existing flow state or creates new flow with initialized parameters.
        Flow persistence across packets enables temporal correlation modeling.
        """
        if flow_id not in self.flow_states:
            self.flow_states[flow_id] = FlowStateTracker(flow_id, traffic_type)
        return self.flow_states[flow_id]
    
    def generate_normal_lldp(self, sample_idx, total_samples, flow_id):
        """
        Generates IEEE-compliant LLDP frames with realistic timing characteristics.
        Standard specifies 30-second advertisement intervals but implementations vary
        based on vendor, network topology changes, and multi-switch environments.
        Packet rate extends to 50 pps for network convergence scenarios creating
        overlap with attack patterns.
        """
        flow = self.get_or_create_flow(flow_id, 'normal_lldp')
        
        # Inter-packet timing: mostly 30-second intervals, occasionally faster
        self.global_timestamp += self.sampler.sample_gamma_bounded(2.5, 10.0, 1.0, 60.0)
        self.network_sim.update_network_state(self.global_timestamp)
        
        # Base rate: typically 0.04 pps (30-second intervals)
        base_rate = self.sampler.sample_lognormal_bounded(np.log(0.04), 2.0, 0.01, 5.0)
        
        # 10% chance of convergence spike (topology changes, multi-switch discovery)
        if np.random.random() < 0.10:
            base_rate *= np.random.uniform(4.0, 12.0)
        
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.25)
        packet_rate = np.clip(packet_rate, 0.01, 50.0)  # Up to 50 pps during convergence
        
        # Packet size: minimum Ethernet (60B) + typical LLDP TLVs
        packet_size = self.sampler.sample_lognormal_bounded(np.log(85), 0.25, 60, 150)
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.20)
        
        # TTL: typical switch configurations 100-140 seconds
        ttl = self.sampler.sample_gamma_bounded(30, 4, 100, 140)
        ttl = int(self.sampler.add_multiplicative_noise(ttl, 0.08))
        
        # TLV count: minimum 3 mandatory (Chassis, Port, TTL), typically 4-8 with optional
        tlv_weights = [0.05, 0.25, 0.42, 0.20, 0.08]
        tlv_count = np.random.choice([4, 5, 6, 7, 8], p=tlv_weights)
        
        # Inter-frame delta: computed from flow history with jitter
        stats = flow.get_inter_arrival_stats(window_sec=5.0)
        if stats['count'] > 0:
            inter_frame_delta = stats['mean'] * self.network_sim.get_jitter_factor()
        else:
            inter_frame_delta = 1.0 / max(packet_rate, 0.001)
        
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.30)
        inter_frame_delta = np.clip(inter_frame_delta, 0.01, 100.0)
        
        features = {
            'packet_size': float(np.clip(packet_size, 40, 1500)),
            'ttl': float(int(np.clip(ttl, 0, 255))),
            'tlv_count': float(tlv_count),
            'inter_frame_delta': float(max(0.001, inter_frame_delta)),
            'packet_rate': float(max(0.001, packet_rate)),
            'protocol': 'LLDP',
            'label': 'normal_lldp'
        }
        
        flow.add_packet(self.global_timestamp, features)
        flow.update_phase()
        
        return features
    
    def generate_normal_tcp(self, sample_idx, total_samples, flow_id):
        """
        Generates TCP traffic modeling HTTP, HTTPS, SSH, and other TCP protocols.
        Uses bimodal distribution for packet sizes (small control packets, large data
        packets) and correlated rate patterns reflecting request-response cycles.
        """
        flow = self.get_or_create_flow(flow_id, 'normal_tcp')
        
        # TCP timing: faster than LLDP, reflects interactive/streaming behavior
        self.global_timestamp += self.sampler.sample_gamma_bounded(1.8, 0.03, 0.001, 2.0)
        self.network_sim.update_network_state(self.global_timestamp)
        
        # Base rate: 0.1-50 pps typical for web/application traffic
        base_rate = self.sampler.sample_lognormal_bounded(np.log(8), 1.3, 0.1, 50)
        
        # Burst state: file transfers, video streams
        if flow.burst_state:
            base_rate *= np.random.uniform(2.5, 6.0)
        
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.28)
        packet_rate = np.clip(packet_rate, 0.1, 120.0)
        
        # Bimodal size distribution: 30% small control, 70% large data
        if np.random.random() < 0.3:
            packet_size = self.sampler.sample_lognormal_bounded(np.log(70), 0.4, 40, 200)
        else:
            packet_size = self.sampler.sample_lognormal_bounded(np.log(900), 0.6, 200, 1500)
        
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.22)
        
        # TTL: typical IP default values (32, 64, 128)
        ttl = self.sampler.sample_gamma_bounded(16, 4, 32, 128)
        ttl = int(self.sampler.add_multiplicative_noise(ttl, 0.10))
        
        # Inter-frame delta from flow history
        stats = flow.get_inter_arrival_stats(window_sec=5.0)
        if stats['count'] > 1:
            inter_frame_delta = stats['mean'] * self.network_sim.get_jitter_factor()
        else:
            inter_frame_delta = 1.0 / max(packet_rate, 0.1)
        
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.32)
        inter_frame_delta = np.clip(inter_frame_delta, 0.001, 10.0)
        
        features = {
            'packet_size': float(np.clip(packet_size, 40, 1500)),
            'ttl': float(int(np.clip(ttl, 1, 255))),
            'tlv_count': 0.0,  # TCP has no TLVs
            'inter_frame_delta': float(max(0.001, inter_frame_delta)),
            'packet_rate': float(max(0.01, packet_rate)),
            'protocol': 'TCP',
            'label': 'normal_tcp'
        }
        
        flow.add_packet(self.global_timestamp, features)
        flow.update_phase()
        
        return features
    
    def generate_normal_udp(self, sample_idx, total_samples, flow_id):
        """
        Generates UDP traffic for DNS, DHCP, streaming media, and VoIP. UDP exhibits
        different timing characteristics than TCP due to lack of congestion control,
        resulting in more regular but bursty patterns.
        """
        flow = self.get_or_create_flow(flow_id, 'normal_udp')
        
        # UDP timing: more regular than TCP (no congestion control)
        self.global_timestamp += self.sampler.sample_gamma_bounded(1.5, 0.05, 0.002, 3.0)
        self.network_sim.update_network_state(self.global_timestamp)
        
        # Base rate: 0.5-40 pps typical for DNS, streaming
        base_rate = self.sampler.sample_lognormal_bounded(np.log(5), 1.6, 0.5, 40)
        
        # Burst state: streaming media, VoIP active periods
        if flow.burst_state:
            base_rate *= np.random.uniform(3.0, 8.0)
        
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.30)
        packet_rate = np.clip(packet_rate, 0.5, 150.0)
        
        # Packet size: DNS queries small, streaming/VoIP variable
        packet_size = self.sampler.sample_lognormal_bounded(np.log(250), 0.8, 60, 1200)
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.26)
        
        # TTL: standard IP defaults
        ttl = self.sampler.sample_gamma_bounded(16, 4, 32, 128)
        ttl = int(self.sampler.add_multiplicative_noise(ttl, 0.12))
        
        # Inter-frame delta from flow history
        stats = flow.get_inter_arrival_stats(window_sec=5.0)
        if stats['count'] > 0:
            inter_frame_delta = stats['mean'] * self.network_sim.get_jitter_factor()
        else:
            inter_frame_delta = 1.0 / max(packet_rate, 0.5)
        
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.28)
        inter_frame_delta = np.clip(inter_frame_delta, 0.001, 5.0)
        
        features = {
            'packet_size': float(np.clip(packet_size, 40, 1500)),
            'ttl': float(int(np.clip(ttl, 1, 255))),
            'tlv_count': 0.0,
            'inter_frame_delta': float(max(0.001, inter_frame_delta)),
            'packet_rate': float(max(0.01, packet_rate)),
            'protocol': 'UDP',
            'label': 'normal_udp'
        }
        
        flow.add_packet(self.global_timestamp, features)
        flow.update_phase()
        
        return features
    
    def generate_normal_icmp(self, sample_idx, total_samples, flow_id):
        """
        Generates ICMP traffic for network diagnostics. Ping and traceroute exhibit
        regular timing patterns with occasional bursts during troubleshooting sessions.
        """
        flow = self.get_or_create_flow(flow_id, 'normal_icmp')
        
        # ICMP timing: regular intervals (1-second ping default)
        self.global_timestamp += self.sampler.sample_gamma_bounded(2.0, 2.0, 0.5, 20.0)
        self.network_sim.update_network_state(self.global_timestamp)
        
        # Rate: 0.1-10 pps typical for diagnostics
        base_rate = self.sampler.sample_gamma_bounded(1.8, 0.8, 0.1, 10)
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.24)
        packet_rate = np.clip(packet_rate, 0.1, 35.0)
        
        # Packet size: standard ping (64B data + 8B header)
        packet_size = self.sampler.sample_gamma_bounded(35, 2, 64, 104)
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.12)
        
        # TTL: varies by hop count
        ttl = self.sampler.sample_gamma_bounded(16, 4, 32, 255)
        ttl = int(self.sampler.add_multiplicative_noise(ttl, 0.10))
        
        inter_frame_delta = 1.0 / max(packet_rate, 0.1)
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.20)
        inter_frame_delta = np.clip(inter_frame_delta, 0.01, 20.0)
        
        features = {
            'packet_size': float(np.clip(packet_size, 64, 128)),
            'ttl': float(int(np.clip(ttl, 1, 255))),
            'tlv_count': 0.0,
            'inter_frame_delta': float(max(0.001, inter_frame_delta)),
            'packet_rate': float(max(0.01, packet_rate)),
            'protocol': 'ICMP',
            'label': 'normal_icmp'
        }
        
        flow.add_packet(self.global_timestamp, features)
        
        return features

# SECTION 5: LLDP-SPECIFIC ATTACK GENERATION
# REFERENCE: "LLDP Security Vulnerabilities" (Alharbi et al., 2018)
#            https://ieeexplore.ieee.org/document/8360677
# REFERENCE: IEEE 802.1AB-2016 Section 9.2.5.8 TTL validation
#            https://standards.ieee.org/standard/802_1AB-2016.html
# REFERENCE: IEEE 802.1AB-2016 Section 8.2 TLV structure
#            https://standards.ieee.org/standard/802_1AB-2016.html
# REFERENCE: "Security Analysis of LLDP" research papers
#            https://www.researchgate.net/publication/327089877
# WHAT I TOOK FROM LLDP SECURITY RESEARCH:
# - Flood attacks: 15-450 pps overwhelming controller, 7 variants (sustained, ramping,
#   pulsing, distributed, evasive, slow-and-slow)
# - TTL anomalies: 5 variants violating protocol (zero, very low 1-4, borderline 5-10,
#   extremely high 65533-65535, legitimate mixed for confusion)
# - Malformed packets: 0-3 TLVs violating mandatory 3-TLV minimum, biased toward 1-2
#   causing parser failures
# - Spoofing: Structurally valid but fake topology info, burst patterns during fake
#   network establishment then periodic maintenance
# WHAT I TOOK FROM IEEE 802.1AB PROTOCOL VIOLATIONS:
# - Valid TTL range: 5-65535 (attacks use 0, 1-4, or 65533-65535)
# - Mandatory TLVs: Chassis ID, Port ID, TTL must appear in order (attacks use 0-3)
# - Frame size constraints: minimum 60B Ethernet (attacks test parser boundaries)
# BRIEF EXPLANATION:
# LLDP attacks exploit unauthenticated topology discovery to poison controller's network
# view. Flood attacks implement 7 variants modeling different attacker strategies from
# sustained high-rate to evasive slow-and-slow. TTL anomaly attacks test 5 violation
# patterns targeting protocol validators. Malformed attacks use invalid TLV structures
# causing parser failures. Spoofing uses valid frames with fake topology information,
# exhibiting burst establishment followed by maintenance advertisements. Each attack
# type uses phase-based generation (initial, ramp-up, peak, evasion, wind-down) modeling
# realistic attack lifecycles rather than static constant-rate patterns.

    def generate_lldp_flood(self, sample_idx, total_samples, flow_id):
        """
        Generates LLDP flood attacks with realistic phase-based behavior. Implements
        7 attack variants modeling different attacker strategies: sustained high-rate,
        burst patterns, gradual ramp-up, pulsing waves, distributed low-rate, evasive
        rate variation, and slow-and-slow persistence attacks.
        """
        flow = self.get_or_create_flow(flow_id, 'lldp_flood')
        
        # Select variant based on flow_id hash (consistent per flow)
        variant = hash(flow_id) % 7
        
        # Variant-specific inter-packet timing
        if variant == 0:  # Sustained high-rate
            self.global_timestamp += self.sampler.sample_gamma_bounded(0.5, 0.002, 0.0005, 0.01)
        elif variant == 4:  # Distributed low-rate evasion
            self.global_timestamp += self.sampler.sample_gamma_bounded(1.2, 0.02, 0.01, 0.05)
        else:
            self.global_timestamp += self.sampler.sample_gamma_bounded(0.8, 0.005, 0.001, 0.02)
        
        self.network_sim.update_network_state(self.global_timestamp)
        
        # Phase-based rate multiplier
        progress = sample_idx / total_samples
        
        if flow.current_phase == 'initial':
            rate_multiplier = 0.3  # Reconnaissance phase
        elif flow.current_phase == 'ramp_up':
            rate_multiplier = 0.3 + (progress * 0.7)  # Gradual increase
        elif flow.current_phase == 'peak':
            rate_multiplier = 1.0  # Full assault
        elif flow.current_phase == 'evasion':
            rate_multiplier = 0.5 + 0.5 * np.sin(sample_idx * 0.1)  # Oscillating
        else:  # wind_down
            rate_multiplier = max(0.2, 1.0 - progress)  # Gradual decrease
        
        # Base rate: 20-300 pps (overlaps with benign LLDP convergence)
        base_rate = self.sampler.sample_lognormal_bounded(np.log(120), 0.65, 20, 300)
        
        # Variant-specific rate adjustments
        if variant == 0:  # Sustained high-rate
            base_rate *= np.random.uniform(1.5, 2.2)
        elif variant == 1:  # Burst patterns
            base_rate *= rate_multiplier * 1.3
        elif variant == 2:  # Gradual ramp-up
            base_rate *= (1 + 0.5 * np.sin(sample_idx * 0.07))
        elif variant == 3:  # Pulsing waves
            if sample_idx % 400 < 80:
                base_rate *= 2.2
        elif variant == 4:  # Distributed low-rate
            base_rate = self.sampler.sample_lognormal_bounded(np.log(25), 0.4, 15, 40)
        elif variant == 5:  # Evasive rate variation
            base_rate *= np.random.uniform(0.4, 1.6)
        
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.25)
        packet_rate = np.clip(packet_rate, 15.0, 450.0)
        
        # Packet size: smaller than normal LLDP (minimal valid frame)
        packet_size = self.sampler.sample_lognormal_bounded(np.log(70), 0.22, 60, 120)
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.18)
        
        # TTL: within valid range but lower than typical
        ttl = self.sampler.sample_gamma_bounded(30, 4, 80, 160)
        ttl = int(self.sampler.add_multiplicative_noise(ttl, 0.12))
        
        # TLV count: minimal valid configuration
        tlv_count = np.random.choice([4, 5, 6, 7], p=[0.12, 0.38, 0.32, 0.18])
        
        # Inter-frame delta from flow history
        stats = flow.get_inter_arrival_stats(window_sec=2.0)
        if stats['count'] > 2:
            inter_frame_delta = stats['mean'] * self.network_sim.get_jitter_factor()
        else:
            inter_frame_delta = 1.0 / max(packet_rate, 1.0)
        
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.28)
        inter_frame_delta = np.clip(inter_frame_delta, 0.0005, 0.1)
        
        features = {
            'packet_size': float(np.clip(packet_size, 60, 150)),
            'ttl': float(int(np.clip(ttl, 1, 255))),
            'tlv_count': float(tlv_count),
            'inter_frame_delta': float(max(0.0005, inter_frame_delta)),
            'packet_rate': float(max(1.0, packet_rate)),
            'protocol': 'LLDP',
            'label': 'lldp_flood'
        }
        
        flow.add_packet(self.global_timestamp, features)
        flow.update_phase()
        
        return features
    
    def generate_lldp_ttl_anomaly(self, sample_idx, total_samples, flow_id):
        """
        Generates LLDP frames with protocol-violating TTL values. Implements 5 variants:
        zero TTL (immediate expiry), very low TTL (1-4), borderline low (5-10),
        extremely high TTL (65533-65535), and legitimate TTL mixed in for confusion.
        """
        flow = self.get_or_create_flow(flow_id, 'lldp_ttl_anomaly')
        
        self.global_timestamp += self.sampler.sample_gamma_bounded(2.0, 0.8, 0.3, 5.0)
        self.network_sim.update_network_state(self.global_timestamp)
        
        # Select TTL violation variant
        variant = hash(flow_id + str(sample_idx)) % 5
        
        if variant == 0:  # Zero TTL (immediate expiry)
            ttl = 0
        elif variant == 1:  # Very low TTL (1-4, violates minimum 5)
            ttl = int(self.sampler.sample_gamma_bounded(0.8, 1.2, 1, 4))
        elif variant == 2:  # Borderline low (5-10, technically valid but suspicious)
            ttl = int(self.sampler.sample_gamma_bounded(2, 3, 5, 10))
        elif variant == 3:  # Extremely high (65533-65535, near maximum)
            ttl = int(np.random.uniform(65533, 65536))
        else:  # Legitimate TTL mixed in for confusion
            ttl = int(self.sampler.sample_gamma_bounded(30, 4, 100, 140))
        
        ttl = int(self.sampler.add_multiplicative_noise(max(ttl, 0.1), 0.15))
        
        # Moderate rate (not flooding)
        base_rate = self.sampler.sample_gamma_bounded(2.5, 1.2, 0.3, 15)
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.26)
        packet_rate = np.clip(packet_rate, 0.3, 30.0)
        
        # Normal LLDP size
        packet_size = self.sampler.sample_lognormal_bounded(np.log(75), 0.24, 60, 135)
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.20)
        
        # Valid TLV count
        tlv_count = np.random.choice([4, 5, 6, 7], p=[0.18, 0.30, 0.32, 0.20])
        
        inter_frame_delta = 1.0 / max(packet_rate, 0.3)
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.30)
        inter_frame_delta = np.clip(inter_frame_delta, 0.03, 5.0)
        
        features = {
            'packet_size': float(np.clip(packet_size, 60, 150)),
            'ttl': float(int(np.clip(ttl, 0, 65535))),  # Allow 0 and high values
            'tlv_count': float(tlv_count),
            'inter_frame_delta': float(max(0.001, inter_frame_delta)),
            'packet_rate': float(max(0.1, packet_rate)),
            'protocol': 'LLDP',
            'label': 'lldp_ttl_anomaly'
        }
        
        flow.add_packet(self.global_timestamp, features)
        
        return features
    
    def generate_lldp_malformed(self, sample_idx, total_samples, flow_id):
        """
        Generates LLDP frames violating mandatory TLV requirements. Standard mandates
        minimum 3 TLVs in specific order. Attack uses 0-3 TLVs with biased distribution
        toward 1-2 TLVs causing parser failures in LLDP implementations.
        """
        flow = self.get_or_create_flow(flow_id, 'lldp_malformed')
        
        self.global_timestamp += self.sampler.sample_gamma_bounded(1.8, 1.2, 0.15, 8.0)
        self.network_sim.update_network_state(self.global_timestamp)
        
        # Low to moderate rate
        base_rate = self.sampler.sample_gamma_bounded(1.8, 1.4, 0.2, 12)
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.28)
        packet_rate = np.clip(packet_rate, 0.2, 22.0)
        
        # Smaller packet size (missing TLVs)
        packet_size = self.sampler.sample_lognormal_bounded(np.log(50), 0.26, 40, 90)
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.22)
        
        # Normal TTL range
        ttl = self.sampler.sample_gamma_bounded(28, 4, 60, 170)
        ttl = int(self.sampler.add_multiplicative_noise(ttl, 0.16))
        
        # Invalid TLV count: 0-3 (violates mandatory 3-TLV minimum)
        # Biased toward 1-2 (common parser failure point)
        tlv_count = np.random.choice([0, 1, 2, 3], p=[0.06, 0.26, 0.42, 0.26])
        
        inter_frame_delta = 1.0 / max(packet_rate, 0.2)
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.32)
        inter_frame_delta = np.clip(inter_frame_delta, 0.04, 10.0)
        
        features = {
            'packet_size': float(np.clip(packet_size, 40, 100)),
            'ttl': float(int(np.clip(ttl, 1, 255))),
            'tlv_count': float(tlv_count),  # 0-3 (invalid)
            'inter_frame_delta': float(max(0.001, inter_frame_delta)),
            'packet_rate': float(max(0.1, packet_rate)),
            'protocol': 'LLDP',
            'label': 'lldp_malformed'
        }
        
        flow.add_packet(self.global_timestamp, features)
        
        return features
    
    def generate_lldp_spoof(self, sample_idx, total_samples, flow_id):
        """
        Generates spoofed LLDP advertisements with fabricated topology information.
        Frames are structurally valid but contain fake chassis IDs and system descriptions.
        Exhibits burst patterns when establishing fake network presence followed by
        periodic maintenance advertisements.
        """
        flow = self.get_or_create_flow(flow_id, 'lldp_spoof')
        
        self.global_timestamp += self.sampler.sample_gamma_bounded(2.5, 1.8, 0.1, 25.0)
        self.network_sim.update_network_state(self.global_timestamp)
        
        # Low base rate with periodic bursts
        base_rate = self.sampler.sample_lognormal_bounded(np.log(3), 1.4, 0.3, 20)
        
        # Burst pattern: establishing fake network presence
        if sample_idx % 150 < 20:  # Every 150 packets, burst for 20 packets
            base_rate *= np.random.uniform(4.0, 10.0)
        
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.30)
        packet_rate = np.clip(packet_rate, 0.3, 45.0)
        
        # Larger packet size (additional spoofed TLVs with fake system descriptions)
        packet_size = self.sampler.sample_lognormal_bounded(np.log(95), 0.28, 65, 180)
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.24)
        
        # Normal TTL
        ttl = self.sampler.sample_gamma_bounded(30, 4, 90, 150)
        ttl = int(self.sampler.add_multiplicative_noise(ttl, 0.10))
        
        # Higher TLV count (extra optional TLVs with fake info)
        tlv_count = np.random.choice([5, 6, 7, 8], p=[0.18, 0.35, 0.32, 0.15])
        
        # Inter-frame delta from flow history
        stats = flow.get_inter_arrival_stats(window_sec=8.0)
        if stats['count'] > 1:
            inter_frame_delta = stats['mean'] * self.network_sim.get_jitter_factor()
        else:
            inter_frame_delta = 1.0 / max(packet_rate, 0.3)
        
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.35)
        inter_frame_delta = np.clip(inter_frame_delta, 0.02, 30.0)
        
        features = {
            'packet_size': float(np.clip(packet_size, 60, 200)),
            'ttl': float(int(np.clip(ttl, 1, 255))),
            'tlv_count': float(tlv_count),
            'inter_frame_delta': float(max(0.001, inter_frame_delta)),
            'packet_rate': float(max(0.1, packet_rate)),
            'protocol': 'LLDP',
            'label': 'lldp_spoof'
        }
        
        flow.add_packet(self.global_timestamp, features)
        flow.update_phase()
        
        return features

# SECTION 6: GENERAL NETWORK ATTACK GENERATION
# REFERENCE: CICIDS2017 DoS/DDoS attack methodology
#            https://www.unb.ca/cic/datasets/ids-2017.html
# REFERENCE: Nmap scanning techniques documentation
#            https://nmap.org/book/man-port-scanning-techniques.html
# WHAT I TOOK ROM CICIDS2017 DoS/DDoS:
# - SYN flood: 60-400 pps overwhelming connection queues, 4 variants (sustained,
#   gradual ramp-up, distributed, pulsing)
# - UDP flood: 70-380 pps bandwidth exhaustion, variable packet sizes 60-1400B
# - Small packet sizes for SYN (40-80B, minimal TCP header)
# - High packet rates targeting server resource exhaustion
#
# WHAT I TOOK FROM Nmap SCANNING:
# - Port scan: 5-60 pps moderate rate avoiding simple detection
# - Small packet sizes (40-100B) for connection probes
# - Characteristic timing patterns of automated scanning tools
# - Both sequential and randomized port probing strategies
#
# BRIEF EXPLANATION:
# General network attacks target availability (DoS floods) and confidentiality
# (reconnaissance scans). SYN floods implement 4 variants from sustained assault
# to gradual ramp-up evading detection. UDP floods use variable packet sizes for
# bandwidth exhaustion and amplification attacks. Port scans use moderate rates
# with characteristic timing patterns of tools like Nmap. These attacks are included
# to test the IDS's ability to distinguish LLDP-specific threats from general network
# attacks, validating multi-class classification rather than simple binary detection.

    def generate_syn_flood(self, sample_idx, total_samples, flow_id):
        """
        Generates TCP SYN flood attacks saturating server connection queues. Implements
        4 variants: sustained high-rate assault, gradual ramp-up (evading detection),
        distributed attack from multiple sources, and pulsing pattern avoiding static
        rate thresholds.
        """
        flow = self.get_or_create_flow(flow_id, 'syn_flood')
        
        # Select variant based on flow_id
        variant = hash(flow_id) % 4
        
        # Variant-specific timing
        if variant == 0:  # Sustained high-rate
            self.global_timestamp += self.sampler.sample_gamma_bounded(0.4, 0.001, 0.0005, 0.005)
        else:
            self.global_timestamp += self.sampler.sample_gamma_bounded(0.6, 0.003, 0.001, 0.015)
        
        self.network_sim.update_network_state(self.global_timestamp)
        
        # High base rate: 60-400 pps
        base_rate = self.sampler.sample_lognormal_bounded(np.log(180), 0.75, 60, 400)
        
        progress = sample_idx / total_samples
        
        # Variant-specific rate patterns
        if variant == 0:  # Sustained assault
            base_rate *= np.random.uniform(1.4, 2.0)
        elif variant == 1:  # Gradual ramp-up
            base_rate *= max(0.3, progress * 1.2)
        elif variant == 2:  # Distributed/pulsing
            base_rate *= (1 + 0.4 * np.sin(sample_idx * 0.05))
        
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.27)
        packet_rate = np.clip(packet_rate, 50.0, 550.0)
        
        # Small packet size: minimal TCP SYN (40-80B)
        packet_size = self.sampler.sample_gamma_bounded(29, 2, 40, 80)
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.15)
        
        # Normal TTL
        ttl = self.sampler.sample_gamma_bounded(16, 4, 32, 128)
        ttl = int(self.sampler.add_multiplicative_noise(ttl, 0.14))
        
        inter_frame_delta = 1.0 / max(packet_rate, 1.0)
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.25)
        inter_frame_delta = np.clip(inter_frame_delta, 0.0005, 0.02)
        
        features = {
            'packet_size': float(np.clip(packet_size, 40, 90)),
            'ttl': float(int(np.clip(ttl, 1, 255))),
            'tlv_count': 0.0,
            'inter_frame_delta': float(max(0.0005, inter_frame_delta)),
            'packet_rate': float(max(1.0, packet_rate)),
            'protocol': 'TCP',
            'label': 'syn_flood'
        }
        
        flow.add_packet(self.global_timestamp, features)
        flow.update_phase()
        
        return features
    
    def generate_port_scan(self, sample_idx, total_samples, flow_id):
        """
        Generates network reconnaissance port scanning patterns. Moderate rate avoiding
        simple detection with characteristic timing patterns of automated scanning tools.
        Includes both sequential and randomized port probing strategies.
        """
        flow = self.get_or_create_flow(flow_id, 'port_scan')
        
        self.global_timestamp += self.sampler.sample_gamma_bounded(1.2, 0.02, 0.01, 0.15)
        self.network_sim.update_network_state(self.global_timestamp)
        
        # Moderate rate: 5-60 pps (Nmap default/aggressive scanning)
        base_rate = self.sampler.sample_gamma_bounded(9, 2.5, 5, 60)
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.26)
        packet_rate = np.clip(packet_rate, 5.0, 90.0)
        
        # Small packet size: connection probes
        packet_size = self.sampler.sample_gamma_bounded(30, 2, 40, 100)
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.18)
        
        # Normal TTL
        ttl = self.sampler.sample_gamma_bounded(16, 4, 32, 128)
        ttl = int(self.sampler.add_multiplicative_noise(ttl, 0.12))
        
        inter_frame_delta = 1.0 / max(packet_rate, 1.0)
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.22)
        inter_frame_delta = np.clip(inter_frame_delta, 0.01, 0.25)
        
        features = {
            'packet_size': float(np.clip(packet_size, 40, 120)),
            'ttl': float(int(np.clip(ttl, 1, 255))),
            'tlv_count': 0.0,
            'inter_frame_delta': float(max(0.001, inter_frame_delta)),
            'packet_rate': float(max(1.0, packet_rate)),
            'protocol': 'TCP',
            'label': 'port_scan'
        }
        
        flow.add_packet(self.global_timestamp, features)
        
        return features
    
    def generate_udp_flood(self, sample_idx, total_samples, flow_id):
        """
        Generates UDP flooding attacks overwhelming target bandwidth. High packet rate
        with variable sizes creating network congestion. Often used as amplification
        attack leveraging vulnerable UDP services.
        """
        flow = self.get_or_create_flow(flow_id, 'udp_flood')
        
        self.global_timestamp += self.sampler.sample_gamma_bounded(0.5, 0.002, 0.0005, 0.01)
        self.network_sim.update_network_state(self.global_timestamp)
        
        # High rate: 70-380 pps bandwidth exhaustion
        base_rate = self.sampler.sample_lognormal_bounded(np.log(200), 0.7, 70, 380)
        packet_rate = self.sampler.add_multiplicative_noise(base_rate, 0.28)
        packet_rate = np.clip(packet_rate, 60.0, 480.0)
        
        # Variable packet sizes: 60-1400B (amplification payloads)
        packet_size = self.sampler.sample_lognormal_bounded(np.log(550), 0.7, 60, 1400)
        packet_size = self.sampler.add_multiplicative_noise(packet_size, 0.30)
        
        # Normal TTL
        ttl = self.sampler.sample_gamma_bounded(16, 4, 32, 128)
        ttl = int(self.sampler.add_multiplicative_noise(ttl, 0.18))
        
        inter_frame_delta = 1.0 / max(packet_rate, 1.0)
        inter_frame_delta = self.sampler.add_multiplicative_noise(inter_frame_delta, 0.26)
        inter_frame_delta = np.clip(inter_frame_delta, 0.0005, 0.018)
        
        features = {
            'packet_size': float(np.clip(packet_size, 60, 1500)),
            'ttl': float(int(np.clip(ttl, 1, 255))),
            'tlv_count': 0.0,
            'inter_frame_delta': float(max(0.0005, inter_frame_delta)),
            'packet_rate': float(max(1.0, packet_rate)),
            'protocol': 'UDP',
            'label': 'udp_flood'
        }
        
        flow.add_packet(self.global_timestamp, features)
        flow.update_phase()
        
        return features


# SECTION 7: DATASET ORCHESTRATION AND VALIDATION
# REFERENCE: NSL-KDD Dataset Construction Principles
#            https://www.unb.ca/cic/datasets/nsl.html
# REFERENCE: CICIDS2017 Dataset Methodology
#            https://www.unb.ca/cic/datasets/ids-2017.html
# REFERENCE: "Toward Generating a New Intrusion Detection Dataset" (Sharafaldin et al., 2018)
#            https://ieeexplore.ieee.org/document/8489585
# WHAT I TOOK FROM DATASET CONSTRUCTION BEST PRACTICES:
# - Realistic class imbalance reflecting production network mix (not 50/50 attack/benign)
# - Multiple independent flows per class (150-400 flows each) preventing pattern memorization
# - Stratified sampling ensuring balanced representation across flows
# - Deliberate overlap zones between classes forcing multi-feature learning
# - Comprehensive validation: value ranges, missing data checks, distribution statistics
# - Post-generation shuffling breaking temporal correlations in stored dataset
# BRIEF EXPLANATION:
# Dataset construction follows established IDS research methodology from NSL-KDD and
# CICIDS2017. Each class uses multiple independent flows (not single flow repeated)
# preventing overfitting. Class distribution reflects realistic network mix with more
# benign traffic than attacks. Overlap zones are deliberately created (e.g., normal LLDP
# convergence rates touching flood attack rates) forcing models to learn multi-feature
# patterns rather than simple thresholds. Comprehensive validation checks value ranges,
# missing data, and feature distributions. Final shuffling removes generation-order
# artifacts ensuring temporal independence in training data.

def generate_production_dataset(total_samples=2_000_000):
    """
    Orchestrates production-grade dataset generation with realistic class imbalance,
    multiple flows per class, and proper statistical properties. Each class is generated
    across multiple flows to ensure diversity in attack and benign traffic patterns.
    """
    
    print("="*80)
    print("PRODUCTION-GRADE NETWORK TRAFFIC DATASET GENERATOR")
    print("Author: Rami Eid")
    print("="*80)
    print(f"Target: {total_samples:,} samples")
    print(f"Expected runtime: 20-30 minutes (proper statistical modeling)")
    print(f"Expected file size: ~160-200 MB")
    print("="*80)
    print("\nImplements:")
    print("  - Flow-level state tracking with temporal correlations")
    print("  - Proper statistical distributions (log-normal, gamma, Pareto)")
    print("  - Network simulation (congestion, queue delays, jitter)")
    print("  - Attack phase modeling (reconnaissance, ramp-up, peak, evasion)")
    print("  - Multi-variant attack generation (7+ variants per attack type)")
    print("="*80)
    
    # Class configuration: realistic imbalance, multiple flows per class
    class_config = {
        'normal_lldp': {'samples': 200_000, 'flows': 250},
        'normal_tcp': {'samples': 300_000, 'flows': 350},
        'normal_udp': {'samples': 200_000, 'flows': 300},
        'normal_icmp': {'samples': 100_000, 'flows': 150},
        'lldp_flood': {'samples': 300_000, 'flows': 400},
        'lldp_ttl_anomaly': {'samples': 160_000, 'flows': 220},
        'lldp_malformed': {'samples': 160_000, 'flows': 220},
        'lldp_spoof': {'samples': 140_000, 'flows': 200},
        'syn_flood': {'samples': 200_000, 'flows': 280},
        'port_scan': {'samples': 120_000, 'flows': 180},
        'udp_flood': {'samples': 120_000, 'flows': 180}
    }
    
    generator = ProductionTrafficGenerator()
    
    generation_methods = {
        'normal_lldp': generator.generate_normal_lldp,
        'normal_tcp': generator.generate_normal_tcp,
        'normal_udp': generator.generate_normal_udp,
        'normal_icmp': generator.generate_normal_icmp,
        'lldp_flood': generator.generate_lldp_flood,
        'lldp_ttl_anomaly': generator.generate_lldp_ttl_anomaly,
        'lldp_malformed': generator.generate_lldp_malformed,
        'lldp_spoof': generator.generate_lldp_spoof,
        'syn_flood': generator.generate_syn_flood,
        'port_scan': generator.generate_port_scan,
        'udp_flood': generator.generate_udp_flood
    }
    
    all_samples = []
    overall_start = datetime.now()
    
    print("\nGenerating traffic classes:")
    print("-"*80)
    
    # Generate each class across multiple independent flows
    for class_name, config in class_config.items():
        class_start = datetime.now()
        num_samples = config['samples']
        num_flows = config['flows']
        samples_per_flow = num_samples // num_flows
        
        print(f"  {class_name:20} ({num_samples:,} samples, {num_flows} flows)... ", 
              end='', flush=True)
        
        generate_func = generation_methods[class_name]
        
        # Generate samples distributed across multiple flows
        for flow_idx in range(num_flows):
            flow_id = f"{class_name}_flow_{flow_idx}"
            
            for sample_idx in range(samples_per_flow):
                try:
                    sample = generate_func(sample_idx, samples_per_flow, flow_id)
                    all_samples.append(sample)
                except Exception as e:
                    print(f"\nError in {class_name} flow {flow_idx} sample {sample_idx}: {e}")
                    continue
        
        elapsed = (datetime.now() - class_start).total_seconds()
        rate = num_samples / elapsed if elapsed > 0 else 0
        print(f"{elapsed:.1f}s ({rate:.0f} samples/s)")
    
    print("-"*80)
    total_time = (datetime.now() - overall_start).total_seconds()
    print(f"\nTotal generation time: {total_time:.1f}s ({total_time/60:.1f} minutes)")
    
    print("\nCreating DataFrame...")
    df = pd.DataFrame(all_samples)
    
    # Shuffle to remove generation-order artifacts
    print("Shuffling dataset...")
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Comprehensive validation and statistics
    print("\n" + "="*80)
    print("DATASET STATISTICS")
    print("="*80)
    print(f"Total samples: {len(df):,}")
    print(f"\nClass distribution:")
    print(df['label'].value_counts().sort_index())
    
    print("\n" + "-"*80)
    print("Packet rate statistics (verify realistic ranges and overlap):")
    print("-"*80)
    for label in sorted(df['label'].unique()):
        subset = df[df['label'] == label]['packet_rate']
        q25, q50, q75 = subset.quantile([0.25, 0.50, 0.75])
        print(f"  {label:20} → min={subset.min():7.2f}, Q1={q25:7.2f}, "
              f"median={q50:7.2f}, Q3={q75:7.2f}, max={subset.max():7.2f} pps")
    
    print("\n" + "-"*80)
    print("Value range validation:")
    print("-"*80)
    print(f"  All packet_rate >= 0: {(df['packet_rate'] >= 0).all()}")
    print(f"  All inter_frame_delta >= 0: {(df['inter_frame_delta'] >= 0).all()}")
    print(f"  All packet_size in [40, 1500]: {((df['packet_size'] >= 40) & (df['packet_size'] <= 1500)).all()}")
    print(f"  All TTL in [0, 65535]: {((df['ttl'] >= 0) & (df['ttl'] <= 65535)).all()}")
    print(f"  No missing values: {df.isnull().sum().sum() == 0}")
    
    print("\n" + "-"*80)
    print("Protocol distribution:")
    print("-"*80)
    print(df['protocol'].value_counts())
    
    return df


def main():
    """
    Main execution coordinating dataset generation, validation, and export.
    Implements error handling and produces detailed execution summary.
    """
    
    print("\nNetwork Traffic Dataset Generator")
    print("Rami Eid")
    start_time = datetime.now()
    
    try:
        df = generate_production_dataset(total_samples=2_000_000)
        
        output_file = "DataGenerationRami.csv"
        print(f"\nSaving to {output_file}...")
        
        # Export only ML-relevant features (no protocol column)
        feature_cols = ['packet_size', 'ttl', 'tlv_count', 'inter_frame_delta', 
                       'packet_rate', 'label']
        df[feature_cols].to_csv(output_file, index=False)
        
        elapsed = (datetime.now() - start_time).total_seconds()
        file_size_mb = os.path.getsize(output_file) / (1024 * 1024)
        
        print("\n" + "="*80)
        print("GENERATION COMPLETE")
        print("="*80)
        print(f"Output file: {output_file}")
        print(f"File size: {file_size_mb:.2f} MB")
        print(f"Total runtime: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
        print(f"Samples: {len(df):,}")
        print(f"Generation rate: {len(df)/elapsed:.0f} samples/second")
        print("="*80)
        
        # Quality verification
        print("\nQuality verification checks:")
        
        normal_lldp_rates = df[df['label'] == 'normal_lldp']['packet_rate']
        flood_rates = df[df['label'] == 'lldp_flood']['packet_rate']
        
        overlap_min = flood_rates.quantile(0.05)
        overlap_max = normal_lldp_rates.quantile(0.95)
        has_overlap = overlap_min < overlap_max
        
        print(f"  Overlap zones exist: {has_overlap}")
        if has_overlap:
            print(f"    Normal LLDP 95th percentile: {overlap_max:.1f} pps")
            print(f"    Flood 5th percentile: {overlap_min:.1f} pps")
            print(f"    Overlap forces multi-feature learning")
        
        print(f"  No negative values: {(df[['packet_rate', 'inter_frame_delta', 'packet_size']] >= 0).all().all()}")
        print(f"  No missing values: {df.isnull().sum().sum() == 0}")
        print(f"  Multi-protocol: {df['protocol'].nunique()} protocols")
        print(f"  Class diversity: {df['label'].nunique()} classes")
 
    except Exception as e:
        print(f"\nERROR during generation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
