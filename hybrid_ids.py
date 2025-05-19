import warnings
from cryptography.utils import CryptographyDeprecationWarning
with warnings.catch_warnings(action="ignore", category=CryptographyDeprecationWarning):
    from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
import pandas as pd
import time
import os
from colorama import Fore, Style
import string

packet_history = []
model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
trained = False
blocked_ips = set()

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
    score = model.predict(df)[0]
    return score == -1

def format_payload(payload, width=16):
    lines = []
    for i in range(0, len(payload), width):
        chunk = payload[i:i + width]
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        ascii_bytes = ''.join(chr(b) if chr(b) in string.printable and b >= 32 else '.' for b in chunk)
        line = f"{Fore.YELLOW}{hex_bytes:<48}  {ascii_bytes}"
        lines.append(line)
    return '\n'.join(lines)

def block_ip(ip):
    if ip not in blocked_ips:
        print(f"{Fore.YELLOW}[#] Blocking IP: {ip}{Style.RESET_ALL}\n")
        print(f"{Fore.WHITE}====================================================================\n")
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
        blocked_ips.add(ip)

def alert(msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{Fore.RED}[!] ALERT {Fore.BLUE}({timestamp}):\n{msg}{Style.RESET_ALL}")

def analyze_packet(packet):
    global packet_history
    feats = extract_features(packet)
    if feats:
        packet_history.append(feats)
        if len(packet_history) == 200 and not trained:
            train_model()
            return
        if trained and detect_anomaly(feats):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet.sport if (TCP in packet or UDP in packet) else "N/A"
            dst_port = packet.dport if (TCP in packet or UDP in packet) else "N/A"
            payload = bytes(packet.payload)[:64]  # Limit to 64 bytes for clarity
            payload_formatted = format_payload(payload)
            alert(f"{Fore.CYAN}Anomalous packet detected:\n"
                  f"  From: {src_ip}:{src_port}\n"
                  f"  To:   {dst_ip}:{dst_port}\n"
                  f"  Payload:\n{payload_formatted}\n"
                  f"{Fore.WHITE}====================================================================\n")
            block_ip(src_ip)

def start_sniffing(interface="eth0"):
    print(f"{Fore.GREEN}[*] Starting hybrid IDS on {interface}...{Style.RESET_ALL}")
    sniff(iface=interface, prn=analyze_packet, store=False)

if __name__ == "__main__":
    try:
        start_sniffing(interface="eth0")
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\n[+] IDS stopped by user.{Style.RESET_ALL}")

