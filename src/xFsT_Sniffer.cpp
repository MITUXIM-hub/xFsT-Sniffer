#include <pcap.h>
#include <winsock2.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <ctime>
#include <map>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

struct PacketSummary {
    std::string protocol;
    std::string src_ip;
    std::string dst_ip;
    int src_port = 0;
    int dst_port = 0;
    unsigned int length = 0;
};

std::string ipv4_to_string(uint32_t ip) {
    const uint8_t* b = reinterpret_cast<const uint8_t*>(&ip);
    std::ostringstream oss;
    oss << static_cast<int>(b[0]) << '.'
        << static_cast<int>(b[1]) << '.'
        << static_cast<int>(b[2]) << '.'
        << static_cast<int>(b[3]);
    return oss.str();
}

std::string protocol_name(uint8_t proto) {
    switch (proto) {
    case 1: return "ICMP";
    case 6: return "TCP";
    case 17: return "UDP";
    default: return "OTHER";
    }
}

std::string tcp_flags_string(uint8_t flags) {
    std::string s;
    if (flags & 0x01) s += "FIN ";
    if (flags & 0x02) s += "SYN ";
    if (flags & 0x04) s += "RST ";
    if (flags & 0x08) s += "PSH ";
    if (flags & 0x10) s += "ACK ";
    if (flags & 0x20) s += "URG ";
    return s.empty() ? "NONE" : s;
}

struct EthernetHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct IPv4Header {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};

struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
};

struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

void print_banner() {
    std::cout << "\n";
    std::cout << "========================================================\n";
    std::cout << "          xFsT SNIFFER v1.0 - Network Analyzer\n";
    std::cout << "    Professional Packet Capture for Windows/Linux/macOS\n";
    std::cout << "              Xbox PSN PC Gaming Networks\n";
    std::cout << "========================================================\n\n";
}

void print_usage(const char* argv0) {
    std::cout << "[xFsT] Usage: " << argv0 << " -i <device> [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i <device>    Network adapter name or number (required)\n";
    std::cout << "  -c <count>     Number of packets to capture (0 = unlimited)\n";
    std::cout << "  -f <filter>    BPF filter, e.g. tcp, udp, port 80\n";
    std::cout << "  -v             Verbose output (show all packet details)\n";
    std::cout << "  -l             List available network interfaces\n";
    std::cout << "  -h             Show this help message\n\n";
}

void list_interfaces() {
    pcap_if_t* all_devs = nullptr;
    pcap_if_t* d = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {};

    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        std::cerr << "[xFsT Error] pcap_findalldevs failed: " << errbuf << '\n';
        return;
    }

    std::cout << "[xFsT] Available Network Interfaces:\n";
    std::cout << std::string(50, '=') << "\n";
    int n = 0;
    for (d = all_devs; d; d = d->next) {
        std::cout << "  [" << n++ << "] " << d->name;
        if (d->description) {
            std::cout << " - " << d->description;
        }
        std::cout << '\n';
    }
    std::cout << std::string(50, '=') << "\n\n";
    pcap_freealldevs(all_devs);
}

void process_packet(const u_char* packet, unsigned int len, bool verbose, 
                    unsigned long long& total_packets, unsigned long long& total_bytes,
                    std::map<std::string, int>& protocol_stats) {
    total_packets++;
    total_bytes += len;

    if (len < sizeof(EthernetHeader)) {
        return;
    }

    const auto* eth = reinterpret_cast<const EthernetHeader*>(packet);
    uint16_t ether_type = ntohs(eth->type);

    if (ether_type != 0x0800) {
        if (verbose && ether_type == 0x0806) {
            std::cout << "[ARP] len=" << len << " bytes\n";
            protocol_stats["ARP"]++;
        }
        return;
    }

    if (len < sizeof(EthernetHeader) + sizeof(IPv4Header)) {
        return;
    }

    const auto* ip = reinterpret_cast<const IPv4Header*>(packet + sizeof(EthernetHeader));
    uint8_t proto = ip->protocol;
    std::string protocol = protocol_name(proto);

    PacketSummary s;
    s.protocol = protocol;
    s.src_ip = ipv4_to_string(ip->src);
    s.dst_ip = ipv4_to_string(ip->dst);
    s.length = len;

    protocol_stats[protocol]++;

    const uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    const u_char* payload = packet + sizeof(EthernetHeader) + ihl;

    if (proto == 6) {
        if (len >= sizeof(EthernetHeader) + ihl + sizeof(TcpHeader)) {
            const auto* tcp = reinterpret_cast<const TcpHeader*>(payload);
            s.src_port = ntohs(tcp->src_port);
            s.dst_port = ntohs(tcp->dst_port);
            
            std::cout << "[TCP] " << s.src_ip << ':' << s.src_port << " -> "
                      << s.dst_ip << ':' << s.dst_port 
                      << " | Flags: " << tcp_flags_string(tcp->flags);
            
            if (verbose) {
                std::cout << " | len=" << len << " bytes | seq=" << ntohl(tcp->seq);
            }
            std::cout << "\n";
        }
    } else if (proto == 17) {
        if (len >= sizeof(EthernetHeader) + ihl + sizeof(UdpHeader)) {
            const auto* udp = reinterpret_cast<const UdpHeader*>(payload);
            s.src_port = ntohs(udp->src_port);
            s.dst_port = ntohs(udp->dst_port);
            
            std::cout << "[UDP] " << s.src_ip << ':' << s.src_port << " -> "
                      << s.dst_ip << ':' << s.dst_port;
            
            if (verbose) {
                std::cout << " | len=" << len << " bytes";
            }
            std::cout << "\n";
        }
    } else if (proto == 1) {
        std::cout << "[ICMP] " << s.src_ip << " -> " << s.dst_ip;
        if (verbose) {
            std::cout << " | len=" << len << " bytes";
        }
        std::cout << "\n";
    } else {
        std::cout << "[" << protocol << "] " << s.src_ip << " -> " << s.dst_ip;
        if (verbose) {
            std::cout << " | len=" << len << " bytes";
        }
        std::cout << "\n";
    }
}

int main(int argc, char** argv) {
    print_banner();

    std::string device;
    std::string filter;
    int packet_limit = 0;
    bool verbose = false;
    bool list = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-l" || arg == "--list") {
            list = true;
        } else if (arg == "-i" && i + 1 < argc) {
            device = argv[++i];
        } else if (arg == "-c" && i + 1 < argc) {
            packet_limit = std::stoi(argv[++i]);
        } else if (arg == "-f" && i + 1 < argc) {
            filter = argv[++i];
        } else if (arg == "-v") {
            verbose = true;
        }
    }

    if (list) {
        list_interfaces();
        return 0;
    }

    if (device.empty()) {
        std::cerr << "[xFsT Error] No device specified!\n";
        print_usage(argv[0]);
        return 1;
    }

    pcap_if_t* all_devs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        std::cerr << "[xFsT Error] Failed to list interfaces: " << errbuf << '\n';
        return 1;
    }

    std::vector<std::string> names;
    for (pcap_if_t* d = all_devs; d; d = d->next) {
        names.push_back(d->name ? d->name : "");
    }

    std::string real_device = device;
    if (!device.empty() && device.find_first_not_of("0123456789") == std::string::npos) {
        int index = std::stoi(device);
        if (index >= 0 && index < static_cast<int>(names.size())) {
            real_device = names[index];
        }
    }

    std::cout << "[xFsT] Opening interface: " << real_device << "\n";
    std::cout << "[xFsT] Admin/Root privileges required\n\n";

    pcap_t* handle = pcap_open_live(real_device.c_str(), 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "[xFsT Error] Could not open device: " << errbuf << '\n';
        std::cerr << "[xFsT] Make sure:\n";
        std::cerr << "       - Device name is correct\n";
        std::cerr << "       - Running as Administrator (Windows) or with sudo (Linux/macOS)\n";
        std::cerr << "       - Npcap/libpcap is installed\n";
        pcap_freealldevs(all_devs);
        return 1;
    }

    if (!filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "[xFsT Error] Bad filter '" << filter << "': " << pcap_geterr(handle) << '\n';
            pcap_close(handle);
            pcap_freealldevs(all_devs);
            return 1;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "[xFsT Error] Error setting filter: " << pcap_geterr(handle) << '\n';
            pcap_freecode(&fp);
            pcap_close(handle);
            pcap_freealldevs(all_devs);
            return 1;
        }
        pcap_freecode(&fp);
        std::cout << "[xFsT] Filter: " << filter << "\n";
    } else {
        std::cout << "[xFsT] Filter: None (all packets)\n";
    }

    std::cout << "[xFsT] Max packets: " << (packet_limit == 0 ? "Unlimited" : std::to_string(packet_limit)) << "\n";
    std::cout << "[xFsT] Verbose: " << (verbose ? "Yes" : "No") << "\n";
    std::cout << "[xFsT] " << std::string(50, '=') << "\n";
    std::cout << "[xFsT] Starting packet capture. Press Ctrl+C to stop.\n\n";

    unsigned long long captured = 0;
    unsigned long long total_bytes = 0;
    std::map<std::string, int> protocol_stats;
    int count = 0;

    while (packet_limit == 0 || count < packet_limit) {
        struct pcap_pkthdr header;
        const u_char* packet = pcap_next(handle, &header);
        if (!packet) {
            continue;
        }

        process_packet(packet, header.len, verbose, captured, total_bytes, protocol_stats);
        ++count;
    }

    std::cout << "\n[xFsT] " << std::string(50, '=') << "\n";
    std::cout << "[xFsT] CAPTURE STATISTICS\n";
    std::cout << "[xFsT] " << std::string(50, '=') << "\n";
    std::cout << "[xFsT] Total packets captured: " << captured << "\n";
    std::cout << "[xFsT] Total bytes captured: " << total_bytes << " bytes\n";
    if (captured > 0) {
        std::cout << "[xFsT] Average packet size: " << (total_bytes / captured) << " bytes\n";
    }
    
    std::cout << "\n[xFsT] Protocol Distribution:\n";
    std::cout << "[xFsT] " << std::string(50, '-') << "\n";
    for (const auto& proto : protocol_stats) {
        double percentage = (static_cast<double>(proto.second) / captured) * 100;
        std::cout << "[xFsT] " << std::setw(10) << std::left << proto.first << ": "
                  << std::setw(8) << proto.second << " ("
                  << std::fixed << std::setprecision(2) << percentage << "%)\n";
    }

    std::cout << "\n[xFsT] " << std::string(50, '=') << "\n";
    std::cout << "[xFsT] Capture complete. Exiting.\n\n";

    pcap_close(handle);
    pcap_freealldevs(all_devs);
    return 0;
}
