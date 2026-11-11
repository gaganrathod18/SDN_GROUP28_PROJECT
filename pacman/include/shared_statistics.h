#ifndef PACMAN_SHARED_STATISTICS_H
#define PACMAN_SHARED_STATISTICS_H

#include "pacman_types.h"
#include <chrono>
#include <deque>
#include <mutex>
#include <cstdint>

namespace PacMan {

/**
 * @brief Thread-safe container for all global engine statistics.
 * 
 * Aggregates data from the packet capture, flow tracking, and threat detection
 * threads so it can be safely read by the UI and reporting engine.
 */
class SharedStatistics {
public:
    /**
     * @brief Records a processed packet and updates flow/traffic statistics.
     */
    void recordPacket(const Flow& flow, uint64_t packet_bytes, uint64_t active_flows);
    
    /**
     * @brief Records a security alert.
     */
    void recordAlert(const Alert& alert);
    
    /**
     * @brief Records a DNS query.
     */
    void recordDns(const std::string& query, const std::string& src_ip);
    
    /**
     * @brief Records the result of a Threat Intelligence lookup.
     */
    void recordThreatIntel(bool is_malicious);
    
    /**
     * @brief Updates the active firewall rules list.
     */
    void updateFirewallRules(const std::vector<FirewallRule>& rules);

    /**
     * @brief Records how blocks are enforced, for display.
     */
    void setFirewallMode(const std::string& mode, const std::string& blocklist_file);
    
    /**
     * @brief Creates a safe copy of the current statistics for UI rendering or reports.
     */
    [[nodiscard]] StatsSnapshot snapshot() const;

private:
    mutable std::mutex mutex_;
    StatsSnapshot stats_;

    struct RateSample {
        std::chrono::steady_clock::time_point time;
        uint64_t pkts;
        uint64_t bytes;
    };
    std::deque<RateSample> rate_window_;
};

} // namespace PacMan

#endif // PACMAN_SHARED_STATISTICS_H
