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
#include <csignal>

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

        // Print blocked IPs list
        cout << "\033[33m[Blocked IPs]: ";
        bool first = true;
        for (const auto& blocked : blocked_ips) {
            if (!first) cout << ", ";
            cout << blocked;
            first = false;
        }
        cout << "\033[0m\n";
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

void handle_sigint([[maybe_unused]] int sig) {
    cout << "\n\n\033[35m[!] Caught SIGINT (Ctrl+C). Printing blocked IP statistics...\033[0m\n";

    if (blocked_ips.empty()) {
        cout << "\033[33m[*] No IPs were blocked during this session.\033[0m\n";
    } else {
        cout << "\033[36m[*] Total Blocked IPs: " << blocked_ips.size() << "\n";
        cout << "[Blocked IPs]: ";
        bool first = true;
        for (const auto& ip : blocked_ips) {
            if (!first) cout << ", ";
            cout << ip;
            first = false;
        }
        cout << "\033[0m\n";
    }

    exit(0);  // Gracefully exit
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = "eth0";  // Change interface if needed

        // Handle command-line arguments
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            cout << "Usage: " << argv[0] << " [-i <interface>]\n"
                 << "  -i <interface>   Specify network interface to capture (default: eth0)\n"
                 << "  -h, --help       Show this help message\n";
            return 0;
        } else if (arg == "-i" && i + 1 < argc) {
            dev = argv[++i];
        } else {
            cerr << "Unknown option: " << arg << "\nUse -h for help.\n";
            return 1;
        }
    }

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Could not open device " << dev << ": " << errbuf << endl;
        return 1;
    }

    signal(SIGINT, handle_sigint);  // Register CTRL+C handler

    cout << "\033[32m[*] Starting hybrid IDS on " << dev << "...\033[0m\n";
    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    return 0;
}
