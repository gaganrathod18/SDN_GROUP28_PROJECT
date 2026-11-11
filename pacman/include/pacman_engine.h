#ifndef PACMAN_ENGINE_H
#define PACMAN_ENGINE_H

#include "config_manager.h"
#include "firewall_manager.h"
#include "flow_tracker.h"
#include "logger.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "shared_statistics.h"
#include "threat_detector.h"
#include "traffic_classifier.h"
#include "virus_total_client.h"
#include <atomic>
#include <string>

namespace PacMan {

/**
 * @brief The core engine that orchestrates packet capture, processing, and UI rendering.
 * 
 * Sets up the producer-consumer threads, initializes all sub-modules, and manages
 * the lifecycle of both Live Capture mode and Offline PCAP Analysis mode.
 */
class PacManEngine {
public:
    /**
     * @brief Constructs the engine with the given configuration.
     * @param config The application configuration.
     */
    explicit PacManEngine(Config config);

    /**
     * @brief Runs the engine in Live Network Capture mode.
     * @return 0 on success, non-zero on error.
     */
    [[nodiscard]] int runLive();
    
    /**
     * @brief Runs the engine in Offline PCAP Analysis mode.
     * @param pcap_path The path to the PCAP file to analyze.
     * @return 0 on success, non-zero on error.
     */
    [[nodiscard]] int analyzeFile(const std::string& pcap_path);

private:
    Config config_;
    Logger logger_;
    SharedStatistics statistics_;
    FlowTracker flow_tracker_;
    TrafficClassifier classifier_;
    ThreatDetector detector_;
    VirusTotalClient virus_total_;
    FirewallManager firewall_;

    /**
     * @brief Internal helper to process a single raw packet.
     * @param source_name The name of the interface or pcap file (for logging).
     * @param raw The raw packet bytes and timestamp.
     * @return True if processing succeeded, false if the packet was dropped.
     */
    [[nodiscard]] bool processOfflinePacket(const std::string& source_name, const PacketAnalyzer::RawPacket& raw);
    
    /**
     * @brief Internal helper to process a packet after basic IP/TCP headers are parsed.
     * @param parsed The parsed packet headers and payload pointer.
     * @param packet_bytes The total size of the original packet.
     * @param when Capture time of the packet (drives the detector's time window, live and offline).
     * @return True if processing succeeded.
     */
    [[nodiscard]] bool processParsedPacket(const PacketAnalyzer::ParsedPacket& parsed, uint64_t packet_bytes,
                                           ThreatDetector::Clock::time_point when);
};

} // namespace PacMan

#endif // PACMAN_ENGINE_H
