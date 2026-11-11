#include "threat_detector.h"
#include <chrono>
#include <utility>

namespace PacMan {

ThreatDetector::ThreatDetector(Config config) : config_(std::move(config)) {}

std::vector<Alert> ThreatDetector::inspect(const Flow& flow, bool initiated) {
    return inspectAt(flow, initiated, Clock::now());
}

std::vector<Alert> ThreatDetector::inspectAt(const Flow& flow, bool initiated, Clock::time_point now) {
    std::vector<Alert> alerts;
    const std::chrono::system_clock::time_point stamp = std::chrono::system_clock::now();
    const std::chrono::seconds window(config_.detection_window_s);

    if (initiated) {
        // Connection / SYN flood: new connections started by one source inside the window
        std::deque<Clock::time_point>& conns = new_conns_by_source_[flow.key.src_ip];
        conns.push_back(now);
        while (!conns.empty() && now - conns.front() > window) conns.pop_front();

        if (flow.key.protocol == Protocol::TCP && conns.size() > config_.syn_flood_threshold &&
            cooledDown("SYN_FLOOD|" + flow.key.src_ip, now)) {
            alerts.push_back({stamp, flow.key.src_ip, "SYN flood: too many new connections from source IP",
                flow.hostname, Severity::HIGH, flow.key.dst_ip, "SYN_FLOOD"});
        } else if (conns.size() > config_.high_connection_threshold &&
                   cooledDown("HIGH_CONN|" + flow.key.src_ip, now)) {
            alerts.push_back({stamp, flow.key.src_ip, "High connection count from source IP",
                flow.hostname, Severity::MEDIUM, flow.key.dst_ip, "HIGH_CONN"});
        }

        // Port scan: distinct destination ports this source opened on one host inside the window
        const std::string key = sourceHostKey(flow);
        std::map<uint16_t, Clock::time_point>& ports = ports_by_source_host_[key];
        ports[flow.key.dst_port] = now;
        for (auto it = ports.begin(); it != ports.end();) {
            it = (now - it->second > window) ? ports.erase(it) : std::next(it);
        }
        if (ports.size() > config_.port_scan_threshold && cooledDown("PORT_SCAN|" + key, now)) {
            alerts.push_back({stamp, flow.key.src_ip, "Possible port scan detected",
                flow.hostname, Severity::HIGH, flow.key.dst_ip, "PORT_SCAN"});
        }
    }

    // Flag unknown domains for newly observed flows
    if (flow.packets == 1 && flow.classification == "Unknown" && !flow.hostname.empty()) {
        alerts.push_back({stamp, flow.key.src_ip, "Unknown domain observed",
            flow.hostname, Severity::LOW, flow.key.dst_ip, "UNKNOWN_DOM"});
    }

    // Large transfer: once per flow, when it first crosses the threshold
    if (flow.bytes > config_.large_transfer_bytes && large_flows_alerted_.insert(flow.key.toString()).second) {
        alerts.push_back({stamp, flow.key.src_ip, "Large transfer threshold exceeded",
            flow.hostname, Severity::MEDIUM, flow.key.dst_ip, "LARGE_TX"});
    }

    if (++inspections_ % 4096 == 0) {
        prune(now);
    }
    return alerts;
}

bool ThreatDetector::cooledDown(const std::string& key, Clock::time_point now) {
    // One alert per key per window: a scan that keeps going is reported again in the next window.
    Clock::time_point& until = quiet_until_[key];
    if (now < until) {
        return false;
    }
    until = now + std::chrono::seconds(config_.detection_window_s);
    return true;
}

void ThreatDetector::prune(Clock::time_point now) {
    // Drop state for sources that have been quiet for a whole window, so memory stays bounded.
    const std::chrono::seconds window(config_.detection_window_s);
    for (auto it = new_conns_by_source_.begin(); it != new_conns_by_source_.end();) {
        it = (it->second.empty() || now - it->second.back() > window) ? new_conns_by_source_.erase(it) : std::next(it);
    }
    for (auto it = ports_by_source_host_.begin(); it != ports_by_source_host_.end();) {
        bool stale = true;
        for (const auto& port : it->second) {
            if (now - port.second <= window) { stale = false; break; }
        }
        it = stale ? ports_by_source_host_.erase(it) : std::next(it);
    }
    for (auto it = quiet_until_.begin(); it != quiet_until_.end();) {
        it = (now >= it->second) ? quiet_until_.erase(it) : std::next(it);
    }
    if (large_flows_alerted_.size() > 100000) {
        large_flows_alerted_.clear();
    }
}

std::string ThreatDetector::sourceHostKey(const Flow& flow) {
    return flow.key.src_ip + "->" + flow.key.dst_ip;
}

} // namespace PacMan
