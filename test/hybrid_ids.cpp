#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <set>
#include <ctime>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

using namespace std;

struct PacketFeatures {
    int packet_len;
    int ttl;
    int proto;
    int src_bytes;
    string src_ip;
};

vector<PacketFeatures> packet_history;
set<string> blocked_ips;

// Get current timestamp as string
string get_timestamp() {
    time_t t = time(nullptr);
    tm* now = localtime(&t);
    stringstream ss;
    ss << put_time(now, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Format payload into hex + ASCII
string format_payload(const u_char *data, int length, int width = 16) {
    stringstream ss;

    for (int i = 0; i < length; i += width) {
        stringstream hex_part, ascii_part;

        for (int j = 0; j < width; ++j) {
            if (i + j < length) {
                unsigned char byte = data[i + j];
                hex_part << setw(2) << setfill('0') << hex << (int)byte << " ";
                ascii_part << (isprint(byte) ? (char)byte : '.');
            } else {
                hex_part << "   ";
                ascii_part << " ";
            }
        }

        ss << "\033[33m" << hex_part.str() << "\033[0m  " << ascii_part.str() << '\n';
    }

    return ss.str();
}

// Alert with timestamp
void alert(const string& msg) {
    string timestamp = get_timestamp();
    cout << "\n\033[31m[!] ALERT \033[34m(" << timestamp << ")\033[0m: " << msg << endl;
}

// Block suspicious IP
void block_ip(const string& ip) {
    if (blocked_ips.find(ip) == blocked_ips.end()) {
        cout << "\033[31m[#] Blocking IP: " << ip << "\033[0m\n";
        string cmd = "iptables -A INPUT -s " + ip + " -j DROP";
        int ret = system(cmd.c_str());
        if (ret != 0) {
            cerr << "[!] Failed to run iptables command for IP block: " << cmd << endl;
        }
        blocked_ips.insert(ip);
    }
}

// Simple anomaly check
bool detect_anomaly(const PacketFeatures& f) {
    return (f.ttl < 10 || f.packet_len > 1400);
}

// Packet processing logic
void packet_handler(u_char *, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ip *ip_hdr = (struct ip*)(packet + 14);  // Ethernet header offset
    PacketFeatures feats;

    feats.packet_len = header->len;
    feats.ttl = ip_hdr->ip_ttl;
    feats.proto = ip_hdr->ip_p;
    feats.src_ip = inet_ntoa(ip_hdr->ip_src);
    feats.src_bytes = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4);

    packet_history.push_back(feats);

    if (packet_history.size() >= 200 && detect_anomaly(feats)) {
        alert("Anomalous packet detected from " + feats.src_ip);

        int ip_header_len = ip_hdr->ip_hl * 4;
        int total_ip_len = ntohs(ip_hdr->ip_len);
        int payload_len = total_ip_len - ip_header_len;
        const u_char* payload = (const u_char*)ip_hdr + ip_header_len;
        int display_len = min(payload_len, 64);

        cout << "\033[36m[+] Payload (" << display_len << " bytes):\n"
             << format_payload(payload, display_len) << "\033[0m";

        block_ip(feats.src_ip);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = "eth0";  // Change interface if needed

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Could not open device " << dev << ": " << errbuf << endl;
        return 1;
    }

    cout << "\033[32m[*] Starting hybrid IDS on " << dev << "...\033[0m\n";
    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    return 0;
}

