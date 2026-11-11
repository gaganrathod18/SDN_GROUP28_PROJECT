#ifndef PACMAN_THREAT_DETECTOR_H
#define PACMAN_THREAT_DETECTOR_H

#include "config_manager.h"
#include "pacman_types.h"
#include <chrono>
#include <deque>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstdint>

namespace PacMan {

/**
 * @brief Analyzes network flows to detect potential security threats.
 *
 * Counts the connections each source *initiates* (TCP SYN, or the first packet of a
 * non-TCP flow that is not a reply) inside a sliding time window, so busy servers
 * answering many clients are not mistaken for scanners.
 */
class ThreatDetector {
public:
    using Clock = std::chrono::steady_clock;

    /**
     * @brief Constructs a ThreatDetector with the specified configuration.
     * @param config The configuration settings for thresholds.
     */
    explicit ThreatDetector(Config config);

    /**
     * @brief Inspects a network flow and generates alerts if suspicious activity is detected.
     * @param flow The network flow to inspect (already updated with the current packet).
     * @param initiated True if this packet opens a new connection started by flow.key.src_ip.
     * @return A vector of generated alerts. Empty if no threats are detected.
     */
    [[nodiscard]] std::vector<Alert> inspect(const Flow& flow, bool initiated);

    /**
     * @brief Same as inspect(flow, initiated) with an explicit clock value (used by tests).
     */
    [[nodiscard]] std::vector<Alert> inspectAt(const Flow& flow, bool initiated, Clock::time_point now);

private:
    Config config_;

    std::unordered_map<std::string, std::map<uint16_t, Clock::time_point>> ports_by_source_host_;
    std::unordered_map<std::string, std::deque<Clock::time_point>> new_conns_by_source_;
    std::unordered_map<std::string, Clock::time_point> quiet_until_;   ///< per "TYPE|key" alert cooldown
    std::unordered_set<std::string> large_flows_alerted_;
    uint64_t inspections_ = 0;

    [[nodiscard]] bool cooledDown(const std::string& key, Clock::time_point now);
    void prune(Clock::time_point now);

    /**
     * @brief Generates a unique key for tracking connections between a source and destination.
     */
    [[nodiscard]] static std::string sourceHostKey(const Flow& flow);
};

} // namespace PacMan

#endif // PACMAN_THREAT_DETECTOR_H
