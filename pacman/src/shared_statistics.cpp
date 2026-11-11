#include "shared_statistics.h"
#include <algorithm>
#include <chrono>

namespace PacMan {

void SharedStatistics::recordPacket(const Flow& flow, uint64_t packet_bytes, uint64_t active_flows) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_packets += 1;
    stats_.total_bytes += packet_bytes;
    stats_.active_flows = active_flows;

    if (flow.key.protocol == Protocol::TCP)       stats_.tcp_packets += 1;
    else if (flow.key.protocol == Protocol::UDP)  stats_.udp_packets += 1;
    else                                          stats_.other_packets += 1;

    stats_.traffic_by_class[flow.classification] += packet_bytes;
    if (!flow.hostname.empty()) {
        stats_.top_domains[flow.hostname] += 1;
    }
    
    // Top talkers: bytes per source IP
    stats_.top_talkers[flow.key.src_ip] += packet_bytes;

    // Live rate: bytes and packets over a sliding 1-second window
    using Clock = std::chrono::steady_clock;
    const std::chrono::time_point<Clock> now = Clock::now();
    rate_window_.push_back({now, 1, packet_bytes});
    
    // Evict samples older than 1 second
    while (!rate_window_.empty() &&
           std::chrono::duration<double>(now - rate_window_.front().time).count() > 1.0) {
        rate_window_.pop_front();
    }
    
    uint64_t window_bytes = 0;
    uint64_t window_pkts = 0;
    for (const RateSample& s : rate_window_) { 
        window_bytes += s.bytes; 
        window_pkts += s.pkts; 
    }
    stats_.bytes_per_sec   = static_cast<double>(window_bytes);
    stats_.packets_per_sec = static_cast<double>(window_pkts);

    // Keep recent_flows as a de-duplicated sliding window of the most active
    // flows (identified by their FlowKey string). Update in place when the
    // flow key already exists, otherwise append and trim.
    const std::string flow_key_str = flow.key.toString();
    std::vector<Flow>::iterator it = std::find_if(stats_.recent_flows.begin(), stats_.recent_flows.end(),
                           [&flow_key_str](const Flow& f) {
                               return f.key.toString() == flow_key_str;
                           });
                           
    if (it != stats_.recent_flows.end()) {
        *it = flow;  // refresh in-place
    } else {
        stats_.recent_flows.push_back(flow);
        if (stats_.recent_flows.size() > 50) {
            stats_.recent_flows.erase(stats_.recent_flows.begin());
        }
    }
}

void SharedStatistics::recordAlert(const Alert& alert) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Deduplicate: if same src_ip + alert_type already in list, just bump repeat_count
    for (Alert& a : stats_.alerts) {
        if (a.source_ip == alert.source_ip && a.alert_type == alert.alert_type) {
            a.repeat_count++;
            a.timestamp = alert.timestamp; // refresh time
            return;
        }
    }
    stats_.alerts.push_back(alert);
    if (stats_.alerts.size() > 100) {
        stats_.alerts.erase(stats_.alerts.begin());
    }
}

void SharedStatistics::recordDns(const std::string& query, const std::string& src_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    DnsQuery dq;
    dq.timestamp = std::chrono::system_clock::now();
    dq.query = query;
    dq.source_ip = src_ip;
    
    stats_.dns_queries.push_back(dq);
    if (stats_.dns_queries.size() > 100) {
        stats_.dns_queries.erase(stats_.dns_queries.begin());
    }
}

void SharedStatistics::recordThreatIntel(bool is_malicious) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.threat_intel.checked_domains++;
    if (is_malicious) {
        stats_.threat_intel.malicious_domains++;
    }
}

StatsSnapshot SharedStatistics::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    StatsSnapshot copy = stats_;

    // Recompute the live rate at read time, so it falls to zero when traffic stops
    // (recordPacket only refreshes it when a packet arrives).
    const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    uint64_t window_bytes = 0;
    uint64_t window_pkts = 0;
    for (const RateSample& s : rate_window_) {
        if (std::chrono::duration<double>(now - s.time).count() <= 1.0) {
            window_bytes += s.bytes;
            window_pkts += s.pkts;
        }
    }
    copy.bytes_per_sec   = static_cast<double>(window_bytes);
    copy.packets_per_sec = static_cast<double>(window_pkts);
    return copy;
}

void SharedStatistics::setFirewallMode(const std::string& mode, const std::string& blocklist_file) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.firewall_mode = mode;
    stats_.blocklist_file = blocklist_file;
}

void SharedStatistics::updateFirewallRules(const std::vector<FirewallRule>& rules) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.firewall_rules = rules;
}

} // namespace PacMan
