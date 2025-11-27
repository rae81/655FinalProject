# LLDP-Based Intrusion Detection System for SDN Networks

**EECE 655 - Final Project**  
American University of Beirut (AUB)

## Team Members

- **Walid Zubdeh** - Attack Toolkit Development (`scapy_lldp_attacks.py`)
- **Rami Eid** - IDS System, ML Model, Dataset Generation, Topology Setup

---

## Repository Structure

| File | Description | Author |
|------|-------------|--------|
| `scapy_lldp_attacks.py` | LLDP attack toolkit with 8 attack modes (flood, spoof, TTL anomaly, malformed, relay, replay, discovery, capture). Supports PCAP export and metadata logging. | Walid Zubdeh |
| `lldp_ids.py` | Hybrid LLDP IDS for Ryu controller. Implements rule-based validation (<1ms) + ML classification (~45ms) with real-time OpenFlow mitigation. | Rami Eid |
| `DataGenerationRami.py` | Dataset generation script producing 2M samples across 11 classes with realistic network simulation, flow tracking, and statistical sampling. | Rami Eid |
| `MLModelRamieid.ipynb` | Google Colab notebook for ML model training. Trains Random Forest (200 trees, 5 features) achieving 92.47% accuracy. Exports model artifacts. | Rami Eid |
| `topology.py` | Mininet topology script creating 4-switch network with hosts for attack simulation and IDS testing. | Rami Eid |
| `README.md` | Project documentation | Team |

### Model Artifacts (modelRamiEid/ directory - REQUIRED)

**Note:** Model PKL files exceed GitHub's file size limit and could not be uploaded to the repository. 

**chekck out dataset:** [Download Model Files (Google Drive)](https://drive.google.com/file/d/13vtOZ5FV4zOF2o23O7EX8eoCkadRylXa/view?usp=drive_link)

The model directory must contain:
- `lldp_multi_class_model.pkl` - Trained Random Forest model (200 trees, ~50MB)
- `feature_scaler_multi_class.pkl` - StandardScaler with training set parameters
- `feature_list.csv` - Feature column ordering
- `class_mapping.csv` - Class ID to name mapping

**Installation:** Extract the downloaded files when you run the ipynb file into `modelRamiEid/` directory in the same location as `lldp_ids.py`

---

## Demo Video

**Full System Demonstration:**  
[https://youtu.be/e1taoc9TV7s](https://youtu.be/e1taoc9TV7s)

The video demonstrates:
- Mininet topology setup with 4 switches
- IDS detection of 6 attack scenarios
- Real-time mitigation with OpenFlow drop rules
- 100% detection rate with zero false positives

---

## System Requirements

### Software Dependencies
- **Ubuntu 20.04 LTS** (or compatible Linux distribution/ however you would go through the hastle of setting up ryu for Kali Linux)
- **Python 3.8+**
- **Ryu SDN Controller 4.34+**
- **Mininet 2.3.0+**
- **Scapy 2.4.5+** (with LLDP support)
- **scikit-learn 1.0+**
- **Open vSwitch 2.13+**

### Python Packages
```bash
pip install ryu scapy numpy pandas scikit-learn joblib matplotlib seaborn imbalanced-learn
```

---

## Setup Instructions
### RYU execution and scapy are to be done in virtual environment (venv) to avoid dependency and compatibility issues
### 1. Install Ryu SDN Controller
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev

# Install Ryu
pip3 install ryu

# Verify installation
ryu-manager --version
```

### 2. Install Mininet
```bash
# Option A: Native installation
sudo apt-get install mininet

# Option B: From source (recommended for latest version)
git clone https://github.com/mininet/mininet
cd mininet
git checkout 2.3.0
sudo PYTHON=python3 util/install.sh -a

# Verify installation
sudo mn --version
```

### 3. Install Scapy with LLDP Support
```bash
pip3 install scapy[complete]

# Verify LLDP support
python3 -c "from scapy.contrib.lldp import LLDPDU; print('LLDP support OK')"
```

### 4. Install ML Dependencies
```bash
pip3 install scikit-learn==1.0.2 joblib numpy pandas
```

### 5. Clone Repository and Setup Model
```bash
git clone <repo-url>
cd <repo-directory>

# Download model files
# Extract to modelRamiEid/ directory

# Verify model files
ls modelRamiEid/
# Should show:
# lldp_multi_class_model.pkl
# feature_scaler_multi_class.pkl
# feature_list.csv
# class_mapping.csv
```

---

## Demo Instructions

### Complete Demo Setup (Recommended)

This demonstrates the full IDS pipeline with real-time attack detection and mitigation.

#### Terminal 1: Start Ryu Controller with IDS
```bash
ryu-manager lldp_ids.py --verbose
```

Wait for: `LLDP IDS Started - Multi-Class Hybrid Detection`

#### Terminal 2: Start Mininet Topology
```bash
sudo python3 topology.py
```

Wait for Mininet CLI prompt: `mininet>`

#### Terminal 3 (from Mininet CLI): Launch Attack Suite
```bash
mininet> h1 sudo python3 scapy_lldp_attacks.py --mode suite --iface h1-eth0 --rate 50 --duration 60
```

**Attack Suite runs 6 attacks automatically:**
1. LLDP Spoofing (10s)
2. LLDP Flood (10s)
3. TTL Anomaly (10s)
4. Malformed TLV (10s)
5. Discovery (10s)
6. Spoofing Variant (10s)

#### Expected Results
- **Terminal 1 (IDS logs):** Real-time detection messages showing:
  - `[RULE VIOLATION]` for obvious attacks (sub-millisecond)
  - `[ML ATTACK]` for evasive attacks (~45ms latency)
  - `Action: DROPPED + BLOCK FLOW INSTALLED`
  
- **Attack artifacts:** Generated in `run_YYYYMMDDTHHMMSSZ/` directory:
  - `attack.pcap` - Captured attack traffic
  - `attack_meta.json` - Attack parameters and statistics

---

## Individual Attack Examples

### LLDP Flood Attack
```bash
mininet> h1 sudo python3 scapy_lldp_attacks.py --mode flood --iface h1-eth0 --rate 50 --duration 30
```

### LLDP Spoofing Attack
```bash
mininet> h1 sudo python3 scapy_lldp_attacks.py --mode spoof --iface h1-eth0 --chassis "rogue-switch" --port "GigabitEthernet0/1" --rate 10 --duration 20
```

### TTL Anomaly Attack (Zero TTL)
```bash
mininet> h1 sudo python3 scapy_lldp_attacks.py --mode ttl_anomaly --iface h1-eth0 --ttl-anom-val 0 --rate 5 --duration 15
```

### Malformed TLV Attack
```bash
mininet> h1 sudo python3 scapy_lldp_attacks.py --mode malformed --iface h1-eth0 --rate 20 --duration 25
```

### LLDP Capture (Reconnaissance)
```bash
mininet> h1 sudo python3 scapy_lldp_attacks.py --mode capture --iface h1-eth0 --duration 60 --pcap-out reconnaissance.pcap
```

## System Performance

### Detection Accuracy
- **Overall Accuracy:** 92.47% (399,842 test samples)
- **LLDP Flood Detection:** 99.86% F1-score
- **LLDP Spoofing Detection:** 92.21% F1-score
- **Malformed Packets:** 99.25% F1-score
- **TTL Anomalies:** 95.67% F1-score

### Detection Latency
- **Rule-based validation:** <1ms average
- **ML classification:** ~45ms average
- **Total pipeline latency:** <50ms (P95: 65ms)

### Live Testing Results
- **Test Scenarios:** 6 attack types
- **Detection Rate:** 100% (all attacks detected)
- **False Positives:** 0 (zero legitimate LLDP blocked)
- **Mitigation Time:** <100ms (detection + OpenFlow rule installation)

---

## Dataset Details

### Classes (11 total)
**LLDP-Specific Attacks:**
- `lldp_flood` - High-rate LLDP flooding (300k samples)
- `lldp_spoof` - Chassis/Port ID spoofing (140k samples)
- `lldp_malformed` - Invalid TLV structures (160k samples)
- `lldp_ttl_anomaly` - TTL manipulation (160k samples)

**Benign Traffic:**
- `normal_lldp` - Legitimate LLDP (200k samples)
- `normal_tcp` - TCP traffic (300k samples)
- `normal_udp` - UDP traffic (200k samples)
- `normal_icmp` - ICMP/ping (100k samples)

**General Network Attacks:**
- `syn_flood` - TCP SYN flooding (200k samples)
- `udp_flood` - UDP flooding (120k samples)
- `port_scan` - Port scanning (120k samples)

**Total:** 2,000,000 samples, 145MB CSV

### Features (5 total)
1. `packet_size` - Frame size (40-1500 bytes)
2. `ttl` - LLDP TTL value (0-65535 seconds)
3. `tlv_count` - Number of TLVs (0-8)
4. `inter_frame_delta` - Time since last packet (seconds)
5. `packet_rate` - Packets per second in 5s window

---

## Troubleshooting

### IDS Model Loading Fails
```
[ERROR] Model load failed: Model not found
```
**Solution:** Download model files from Google Drive link above and extract to `modelRamiEid/` directory in same location as `lldp_ids.py`

### Scapy LLDP Import Error
```
ImportError: cannot import name 'LLDPDU' from 'scapy.contrib.lldp'
```
**Solution:** Install Scapy with complete extras: `pip3 install scapy[complete]`

### Permission Denied on Attack Script
```
Operation not permitted
```
**Solution:** Run with sudo: `sudo python3 scapy_lldp_attacks.py ...`

### Mininet Cleanup (if topology hangs)
```bash
sudo mn -c
sudo killall -9 ryu-manager
```

---

## References

### Attack Toolkit References
1. **github.com/Lamonkey/SDN_Topology_Attack** - LLDP relay and spoofing
2. **github.com/DichHuynh/Topology-Poisoning-Attack-in-SDN** - Topology poisoning patterns
3. **github.com/SySS-Research/WireBug** - TLV crafting and malformed packets
4. **github.com/profxadke/replay** - PCAP replay utility
5. **github.com/GoozeyX/python_lldp** - LLDP parsing and sniffing

### IDS System References
1. **Ryu SDN Framework** - https://ryu.readthedocs.io/en/latest/
2. **IEEE 802.1AB-2016** - LLDP Protocol Standard
3. **OpenFlow 1.3 Specification** - https://www.opennetworking.org/
4. **scikit-learn Documentation** - Random Forest and model persistence
5. **Zeek Network Security Monitor** - Flow tracking patterns
6. **Snort IDS** - Hybrid detection architecture

in addition to other references mentioned within the other scripts
all scripts are well-documented and you can check them out for section by section details
---

## License

This project is developed for academic purposes as part of EECE 655 coursework at the American University of Beirut.

---

