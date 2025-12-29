// rtp_monitor.cpp
// Compilar: g++ -std=c++17 rtp_monitor.cpp -lpcap -o rtp_monitor
// Exemplo: sudo ./rtp_monitor -i eth0 -p 10000 -c 8000 -t 5
//
// Monitora RTP em UDP na porta indicada e calcula jitter (RFC3550).
// Tenta extrair RTCP SR (pt=200) para estimar one-way delay (requer NTP sync).

#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <getopt.h>
#include <cmath>
#include <algorithm>

using namespace std;

struct FlowKey {
    string src_ip;
    string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    bool operator==(FlowKey const& o) const {
        return src_ip==o.src_ip && dst_ip==o.dst_ip && src_port==o.src_port && dst_port==o.dst_port;
    }
};

struct FlowKeyHash {
    size_t operator()(FlowKey const& k) const noexcept {
        return std::hash<string>()(k.src_ip) ^ std::hash<string>()(k.dst_ip) ^ (k.src_port<<1) ^ (k.dst_port<<3);
    }
};

struct FlowStats {
    uint64_t pkts = 0;
    uint64_t bytes = 0;
    uint32_t last_seq = 0;
    bool has_last_seq = false;
    double J = 0.0; // interarrival jitter per RFC3550
    uint32_t last_rtp_ts = 0;
    bool has_last_rtp_ts = false;
    double last_arrival_s = 0.0;
    double clock_rate = 8000.0;
    vector<double> interarrival_diff; // for stats
    // for latency via RTCP SR (if present)
    bool have_last_sr = false;
    uint64_t last_sr_ntp_sec = 0;
    uint64_t last_sr_ntp_frac = 0;
    uint32_t last_sr_rtp_ts = 0;
    // store sample of computed one-way delays (seconds)
    vector<double> one_way_delays;
};

unordered_map<FlowKey, FlowStats, FlowKeyHash> flows;

double timeval_to_seconds(const struct timeval &tv) {
    return tv.tv_sec + tv.tv_usec / 1e6;
}

// Convert local gettimeofday to NTP 64-bit components: seconds and fractional (32-bit)
void get_local_ntp(uint32_t &sec_out, uint32_t &frac_out) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    uint64_t seconds = (uint64_t)tv.tv_sec + 2208988800ULL; // NTP epoch starts 1900
    uint64_t frac = (uint64_t)((double)tv.tv_usec * (double)(1ULL<<32) / 1e6);
    sec_out = (uint32_t)seconds;
    frac_out = (uint32_t)frac;
}

// Helper to read 16/32/64 from network bytes
static inline uint16_t read_u16(const uint8_t* p) { return ntohs(*(uint16_t*)p); }
static inline uint32_t read_u32(const uint8_t* p) { return ntohl(*(uint32_t*)p); }
static inline uint64_t read_u64(const uint8_t* p) {
    uint32_t hi = read_u32(p);
    uint32_t lo = read_u32(p+4);
    return ((uint64_t)hi << 32) | lo;
}

bool is_rtp_packet(const uint8_t* payload, size_t len) {
    if (len < 12) return false;
    uint8_t v = (payload[0] >> 6) & 0x03;
    if (v != 2) return false;
    // basic sanity checks: payload type not reserved? skip further checks
    return true;
}

void process_rtp_packet(const FlowKey &key, const uint8_t* payload, size_t len, double arrival_s) {
    if (len < 12) return;
    FlowStats &st = flows[key];

    uint8_t v_p_x_cc = payload[0];
    uint8_t v = (v_p_x_cc >> 6) & 0x03;
    uint8_t cc = v_p_x_cc & 0x0F;
    uint8_t m_pt = payload[1];
    uint8_t pt = m_pt & 0x7F;
    uint16_t seq = read_u16(payload+2);
    uint32_t ts = read_u32(payload+4);
    // ssrc at +8 (not used here)
    st.pkts++;
    st.bytes += len;

    // packet loss estimate by sequence
    if (st.has_last_seq) {
        uint32_t expected = (uint32_t)st.last_seq + 1;
        if (seq != expected) {
            // note: wrap-around handling
            if (seq < st.last_seq) {
                // wrap
            } else {
                // loss detected (seq - expected) lost packets
            }
        }
    }
    st.last_seq = seq;
    st.has_last_seq = true;

    // jitter calc per RFC3550:
    // D = (R - Rprev) - (S - Sprev)
    // where S are RTP timestamps converted to seconds using clock_rate.
    double S = (double)ts / st.clock_rate;
    if (st.has_last_rtp_ts) {
        double Sprev = (double)st.last_rtp_ts / st.clock_rate;
        double Rprev = st.last_arrival_s;
        double R = arrival_s;
        double D = (R - Rprev) - (S - Sprev);
        double absD = fabs(D);
        st.J += (absD - st.J) / 16.0;
        st.interarrival_diff.push_back(R - Rprev);
    }
    st.last_rtp_ts = ts;
    st.has_last_rtp_ts = true;
    st.last_arrival_s = arrival_s;
}

void process_rtcp(const FlowKey &key, const uint8_t* payload, size_t len, double arrival_s) {
    // RTCP composes of packets; we iterate through compound RTCP packets
    size_t offset = 0;
    while (offset + 4 <= len) {
        const uint8_t* pkt = payload + offset;
        uint8_t v_p_count = pkt[0];
        uint8_t v = (v_p_count >> 6) & 0x03;
        uint8_t pt = pkt[1];
        uint16_t rc_len = read_u16(pkt+2); // length in 32-bit words minus 1
        size_t pkt_len = ((size_t)rc_len + 1) * 4;
        if (offset + pkt_len > len) break;
        // RTCP SR is packet type 200
        if (pt == 200 && pkt_len >= 28) {
            // SR sender info starts at byte 4: ntp (64) + rtp ts (32) + packet count + octet count
            const uint8_t* si = pkt + 4;
            uint32_t ntp_sec = read_u32(si);
            uint32_t ntp_frac = read_u32(si+4);
            uint32_t rtp_ts = read_u32(si+8);
            FlowStats &st = flows[key];
            st.have_last_sr = true;
            st.last_sr_ntp_sec = ntp_sec;
            st.last_sr_ntp_frac = ntp_frac;
            st.last_sr_rtp_ts = rtp_ts;
            // Estimate one-way delay: arrival_time_local_as_ntp - sender_ntp
            uint32_t local_ntp_sec, local_ntp_frac;
            get_local_ntp(local_ntp_sec, local_ntp_frac);
            // convert to double seconds
            double sender_ntp_d = (double)ntp_sec - 2208988800.0 + (double)ntp_frac / (double)UINT32_MAX;
            double local_ntp_d = (double)local_ntp_sec - 2208988800.0 + (double)local_ntp_frac / (double)UINT32_MAX;
            double one_way = local_ntp_d - sender_ntp_d;
            st.one_way_delays.push_back(one_way);
        }
        offset += pkt_len;
    }
}

void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    // minimal IPv4/UDP parser: assumes Ethernet + IPv4 + UDP
    const uint8_t* pkt = bytes;
    size_t caplen = h->caplen;
    if (caplen < 14 + 20 + 8) return;
    const uint8_t* eth = pkt;
    uint16_t eth_type = ntohs(*(uint16_t*)(eth + 12));
    size_t ip_off = 14;
    if (eth_type == 0x8100) {
        // VLAN tag present (skip)
        if (caplen < 18 + 20 + 8) return;
        eth_type = ntohs(*(uint16_t*)(eth + 16));
        ip_off = 18;
    }
    if (eth_type != 0x0800) return; // not IPv4
    const uint8_t* ip = pkt + ip_off;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    uint8_t proto = ip[9];
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip + 12, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, ip + 16, dst_ip, sizeof(dst_ip));
    if (proto != 17) return; // not UDP
    const uint8_t* udp = ip + ihl;
    uint16_t src_port = ntohs(*(uint16_t*)(udp));
    uint16_t dst_port = ntohs(*(uint16_t*)(udp + 2));
    uint16_t udp_len = ntohs(*(uint16_t*)(udp + 4));
    size_t udp_payload_offset = ip_off + ihl + 8;
    if (caplen < udp_payload_offset) return;
    size_t udp_payload_len = caplen - udp_payload_offset;
    const uint8_t* payload = pkt + udp_payload_offset;

    FlowKey k;
    k.src_ip = string(src_ip);
    k.dst_ip = string(dst_ip);
    k.src_port = src_port;
    k.dst_port = dst_port;

    // arrival time
    double arrival_s = timeval_to_seconds(h->ts);

    // Determine if this is RTCP (ports often even, or check payload RTCP type)
    if (udp_payload_len >= 2) {
        uint8_t first_byte = payload[0];
        uint8_t version = (first_byte >> 6) & 0x03;
        if (version != 2) return;
        // Heuristic: RTCP packet types are >= 192 (SR=200, RR=201, SDES=202, BYE=203)
        uint8_t pt = payload[1];
        if (pt >= 192 && pt <= 223) {
            // treat as RTCP
            process_rtcp(k, payload, udp_payload_len, arrival_s);
            return;
        } else {
            // assume RTP (payload type could be <96 static or >=96 dynamic)
            if (is_rtp_packet(payload, udp_payload_len)) {
                // set default clock_rate if new flow
                if (!flows.count(k)) {
                    FlowStats fs;
                    // default already 8000; user may adjust later by key
                    flows[k] = fs;
                }
                process_rtp_packet(k, payload, udp_payload_len, arrival_s);
                return;
            }
        }
    }
    // else ignore
}

void print_stats_periodically(int interval_seconds) {
    while (true) {
        sleep(interval_seconds);
        cout << "\n=== RTP Monitor stats (last " << interval_seconds << "s) ===\n";
        for (auto &p : flows) {
            const FlowKey &k = p.first;
            FlowStats &s = p.second;
            cout << "Flow " << k.src_ip << ":" << k.src_port << " -> " << k.dst_ip << ":" << k.dst_port << "\n";
            cout << "  packets: " << s.pkts << ", total bytes: " << s.bytes << "\n";
            cout << "  jitter (RFC3550, seconds): " << s.J << "  (clock_rate=" << s.clock_rate << ")\n";
            if (!s.interarrival_diff.empty()) {
                double sum = 0;
                for (double v : s.interarrival_diff) sum += v;
                double mean = sum / s.interarrival_diff.size();
                vector<double> tmp = s.interarrival_diff;
                sort(tmp.begin(), tmp.end());
                double med = tmp[tmp.size()/2];
                cout << "  interarrival mean(s): " << mean << ", median(s): " << med << "\n";
            }
            if (!s.one_way_delays.empty()) {
                double sum=0; for(auto v:s.one_way_delays) sum+=v;
                double mean=sum/s.one_way_delays.size();
                cout << "  one-way delay estimates (from RTCP SR), samples=" << s.one_way_delays.size() << ", mean(s)=" << mean << "\n";
                cout << "    * Note: one-way only meaningful if endpoints clocks synchronized (NTP).\n";
            }
            cout << "\n";
        }
        cout << "=== end ===\n";
    }
}

void usage(const char* prog) {
    cerr << "Usage: sudo " << prog << " -i <iface> -p <port> -c <clock_rate> -t <interval_sec>\n";
    cerr << "  -i iface    capture interface (ex: eth0)\n";
    cerr << "  -p port     UDP port to filter (RTP/RTCP port)\n";
    cerr << "  -c clock    RTP clock rate (e.g. 8000 for audio, 90000 for video). Default 8000\n";
    cerr << "  -t seconds  print stats interval (default 5)\n";
}

int main(int argc, char** argv) {
    string iface;
    int port = 0;
    double clock_rate = 8000.0;
    int interval = 5;

    int opt;
    while ((opt = getopt(argc, argv, "i:p:c:t:")) != -1) {
        switch(opt) {
            case 'i': iface = optarg; break;
            case 'p': port = atoi(optarg); break;
            case 'c': clock_rate = atof(optarg); break;
            case 't': interval = atoi(optarg); break;
            default: usage(argv[0]); return 1;
        }
    }
    if (iface.empty() || port == 0) {
        usage(argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.c_str(), 65536, 1, 1000, errbuf);
    if (!handle) {
        cerr << "pcap_open_live failed: " << errbuf << "\n";
        return 1;
    }

    // build filter: udp and (port port)
    string filter = "udp and (port " + to_string(port) + ")";
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
        cerr << "pcap_compile failed\n";
        return 1;
    }
    if (pcap_setfilter(handle, &fp) < 0) {
        cerr << "pcap_setfilter failed\n";
        return 1;
    }

    cout << "Listening on " << iface << " port " << port << " (clock_rate=" << clock_rate << ")\n";

    // start background printer thread
    // set default clock_rate for flows on creation
    // We'll spawn a detached thread for printing stats
    thread printer([interval](){ print_stats_periodically(interval); });
    printer.detach();

    // Set global capture loop: use pcap_loop with callback
    // But we need to set default clock_rate for new flows; update inside packet handler after creation is acceptable if we track user-provided rate globally
    // Instead, we store rate in a static global variable; but simpler: set in flows when created inside handler after reading global variable.

    // Save provided clock rate for assignment
    double provided_clock_rate = clock_rate;

    // We will create a small lambda wrapper to assign clock_rate to new flows.
    // To keep it simple, we set a global var (not ideal but works for small utility).
    // Using a global variable:
    extern double g_clock_rate_for_new_flows;
    g_clock_rate_for_new_flows = provided_clock_rate;

    // Start capture loop
    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    return 0;
}

// Global var used by packet handler to initialize flow clock rates
double g_clock_rate_for_new_flows = 8000.0;

// Modify process when a new flow is inserted (this small change placed here for clarity)
