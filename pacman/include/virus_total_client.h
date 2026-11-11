#ifndef PACMAN_VIRUS_TOTAL_CLIENT_H
#define PACMAN_VIRUS_TOTAL_CLIENT_H

#include <string>
#include <mutex>
#include <unordered_map>

namespace PacMan {

/**
 * @brief Represents the result of a VirusTotal domain check.
 */
struct VirusTotalResult {
    bool checked = false;       ///< True if a check was successfully performed
    bool malicious = false;     ///< True if VirusTotal marked the domain as malicious
    std::string message;        ///< Human-readable status or error message
};

/**
 * @brief Client for interacting with the VirusTotal API.
 * 
 * Used for looking up suspicious domains. Results are cached in-memory
 * to prevent rate-limiting or redundant network requests.
 */
class VirusTotalClient {
public:
    /**
     * @brief Constructs a new VirusTotal client.
     * @param api_key The API key for VirusTotal. If empty, checks are disabled.
     */
    explicit VirusTotalClient(std::string api_key);
    
    /**
     * @brief Checks if the client has a valid API key and is enabled.
     */
    [[nodiscard]] bool enabled() const { return !api_key_.empty(); }
    
    /**
     * @brief Helper that checks if a domain is malicious.
     * @param domain The domain to check.
     * @return True if the domain is malicious, false otherwise.
     */
    [[nodiscard]] bool isMalicious(const std::string& domain) const;
    
    /**
     * @brief Queries VirusTotal for a domain's reputation, using a local cache.
     * @param domain The domain to check.
     * @return A VirusTotalResult struct with the outcome.
     */
    [[nodiscard]] VirusTotalResult checkDomain(const std::string& domain) const;

private:
    std::string api_key_;
    mutable std::mutex cache_mutex_;
    mutable std::unordered_map<std::string, VirusTotalResult> cache_;
};

} // namespace PacMan

#endif // PACMAN_VIRUS_TOTAL_CLIENT_H
