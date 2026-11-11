#include "traffic_classifier.h"
#include <algorithm>
#include <cctype>
#include <cstdint>

namespace PacMan {

// Well-known Port Constants
static constexpr uint16_t PORT_SSH        = 22;
static constexpr uint16_t PORT_SMTP       = 25;
static constexpr uint16_t PORT_DNS        = 53;
static constexpr uint16_t PORT_HTTP       = 80;
static constexpr uint16_t PORT_HTTPS      = 443;
static constexpr uint16_t PORT_IMAPS      = 993;
static constexpr uint16_t PORT_NTP        = 123;
static constexpr uint16_t PORT_MYSQL      = 3306;
static constexpr uint16_t PORT_POSTGRESQL = 5432;

std::string TrafficClassifier::classify(const std::string& hostname, const FlowKey& key) const {
    // Convert hostname to lowercase for case-insensitive matching.
    std::string lowered = hostname;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

    if (!lowered.empty()) {
        for (const std::pair<std::string, std::string>& entry : service_table_) {
            if (lowered.find(entry.first) != std::string::npos) {
                return entry.second;
            }
        }
        // Hostname present but not in our table — still label by port if possible.
    }

    // Port-based fallback classification.
    const uint16_t dst = key.dst_port;
    const uint16_t src = key.src_port;
    
    if (dst == PORT_DNS || src == PORT_DNS) return "DNS";
    if (dst == PORT_HTTPS || src == PORT_HTTPS) return "HTTPS";
    if (dst == PORT_HTTP || src == PORT_HTTP) return "HTTP";
    if (dst == PORT_SSH || src == PORT_SSH) return "SSH";
    if (dst == PORT_SMTP || src == PORT_SMTP) return "SMTP";
    if (dst == PORT_IMAPS || src == PORT_IMAPS) return "IMAPS";
    if (dst == PORT_NTP || src == PORT_NTP) return "NTP";
    if (dst == PORT_MYSQL || src == PORT_MYSQL) return "MySQL";
    if (dst == PORT_POSTGRESQL || src == PORT_POSTGRESQL) return "PostgreSQL";

    return "Unknown";
}

} // namespace PacMan
