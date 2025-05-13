# hybrid_ids.py

from scapy.all import sniff, IP
from sklearn.ensemble import IsolationForest
import pandas as pd
import time
from colorama import Fore, Style

# History to simulate training data
packet_history = []

# Pre-trained model placeholder (in a real setup you'd train this offline)
model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
trained = False

def extract_features(packet):
    features = {}
    if IP in packet:
        ip = packet[IP]
        features['packet_len'] = len(packet)
        features['ttl'] = ip.ttl
        features['proto'] = ip.proto
        features['src_bytes'] = len(packet.payload)
        return features
    return None

def train_model():
    global model, trained
    df = pd.DataFrame(packet_history)
    if not df.empty:
        model.fit(df)
        trained = True
        print(f"{Fore.CYAN}[+] Anomaly model trained on {len(df)} samples{Style.RESET_ALL}")

def detect_anomaly(features):
    df = pd.DataFrame([features])
    score = model.predict(df)[0]  # -1 = anomaly
    return score == -1

def alert(msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{Fore.RED}[!] ALERT ({timestamp}): {msg}{Style.RESET_ALL}")

def analyze_packet(packet):
    global packet_history

    # Extract and buffer features
    feats = extract_features(packet)
    if feats:
        packet_history.append(feats)
        if len(packet_history) == 200 and not trained:
            train_model()
            return

        if trained and detect_anomaly(feats):
            alert(f"Anomalous packet detected: {packet[IP].src} -> {packet[IP].dst}")

def start_sniffing(interface="eth0"):
    print(f"{Fore.GREEN}[*] Starting hybrid IDS on {interface}...{Style.RESET_ALL}")
    sniff(iface=interface, prn=analyze_packet, store=False)

if __name__ == "__main__":
    try:
        start_sniffing(interface="eth0")  # Replace with your actual interface
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\n[+] IDS stopped by user.{Style.RESET_ALL}")
