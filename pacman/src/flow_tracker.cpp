#include "flow_tracker.h"
#include <chrono>
#include <cstdio>

namespace PacMan {

namespace {

// True for addresses that never leave a local network (RFC 1918, loopback, link-local).
bool isLocalIPv4(const std::string& ip) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    return a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) ||
           (a == 192 && b == 168) || (a == 169 && b == 254);
}

} // namespace

// TCP Flag Constants
static constexpr uint8_t TCP_FLAG_FIN = 0x01;
static constexpr uint8_t TCP_FLAG_SYN = 0x02;
static constexpr uint8_t TCP_FLAG_RST = 0x04;
static constexpr uint8_t TCP_FLAG_PSH = 0x08;
static constexpr uint8_t TCP_FLAG_ACK = 0x10;
static constexpr uint8_t TCP_FLAG_URG = 0x20;

Flow& FlowTracker::updateFlow(const FlowKey& key,
                              const std::string& hostname,
                              const std::string& classification,
                              uint64_t packet_bytes,
                              bool has_tcp,
                              uint8_t tcp_flags) {
    const std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    
    // Find or insert the flow
    std::pair<std::unordered_map<FlowKey, Flow, FlowKeyHash>::iterator, bool> result = flows_.emplace(key, Flow{});
    std::unordered_map<FlowKey, Flow, FlowKeyHash>::iterator it = result.first;
    const bool is_new_flow = result.second;
    
    Flow& flow = it->second;

    // Initialize new flows
    if (is_new_flow) {
        flow.key = key;
        flow.first_seen = now;
        
        // No GeoIP database is bundled: private addresses are "LAN", everything else unknown.
        flow.dst_country = isLocalIPv4(key.dst_ip) ? "LAN" : "—";
    }

    // Update general flow statistics
    flow.last_seen = now;
    flow.packets += 1;
    flow.bytes += packet_bytes;
    
    if (!hostname.empty()) {
        flow.hostname = hostname;
    }
    
    // Only update classification if we don't already have a strong one, 
    // or if the new one is more specific (assuming the caller passes a good classification)
    flow.classification = classification;

    // Update connection state based on TCP flags
    if (has_tcp) {
        if ((tcp_flags & TCP_FLAG_RST) != 0) {
            flow.connection_state = "❌ RST";
        } else if ((tcp_flags & TCP_FLAG_FIN) != 0) {
            flow.connection_state = "🔴 FIN";
        } else if ((tcp_flags & TCP_FLAG_SYN) != 0) {
            if ((tcp_flags & TCP_FLAG_ACK) != 0) {
                flow.connection_state = "🟡 SYN-ACK";
            } else {
                flow.connection_state = "🟡 SYN";
            }
        } else if ((tcp_flags & TCP_FLAG_ACK) != 0) {
            // If we see an ACK and we were in SYN state (or initial state), consider it established
            if (flow.connection_state.find("SYN") != std::string::npos || flow.connection_state == "—") {
                flow.connection_state = "🟢 ESTAB";
            }
        }
    } else {
        flow.connection_state = key.protocol == Protocol::UDP ? "⚪ UDP" : "⚪ —";   // ICMP etc. have no state
    }

    return flow;
}

} // namespace PacMan
