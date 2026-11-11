#ifndef PACMAN_FLOW_TRACKER_H
#define PACMAN_FLOW_TRACKER_H

#include "pacman_types.h"
#include <unordered_map>
#include <string>
#include <cstdint>

namespace PacMan {

/**
 * @brief Manages active network flows and their statistics.
 * 
 * A flow is typically identified by the 5-tuple (src IP, dst IP, src port, dst port, protocol).
 * This class tracks packet counts, bytes, hostnames, and connection states.
 */
class FlowTracker {
public:
    /**
     * @brief Updates an existing flow or creates a new one if it doesn't exist.
     * 
     * @param key The unique identifier for the network flow.
     * @param hostname The extracted hostname (e.g., from SNI or DNS), if available.
     * @param classification The traffic classification label (e.g., "Google", "HTTPS").
     * @param packet_bytes The size of the current packet in bytes.
     * @param has_tcp True if the packet is a TCP packet.
     * @param tcp_flags The TCP flags present in the packet header.
     * @return Reference to the updated Flow object.
     */
    Flow& updateFlow(const FlowKey& key,
                     const std::string& hostname,
                     const std::string& classification,
                     uint64_t packet_bytes,
                     bool has_tcp,
                     uint8_t tcp_flags);

    /**
     * @brief Retrieves the map of all tracked flows.
     * @return A constant reference to the underlying unordered_map of flows.
     */
    [[nodiscard]] const std::unordered_map<FlowKey, Flow, FlowKeyHash>& flows() const {
        return flows_;
    }

private:
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
};

} // namespace PacMan

#endif // PACMAN_FLOW_TRACKER_H
