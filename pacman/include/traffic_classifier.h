#ifndef PACMAN_TRAFFIC_CLASSIFIER_H
#define PACMAN_TRAFFIC_CLASSIFIER_H

#include "pacman_types.h"
#include <string>
#include <vector>
#include <utility>

namespace PacMan {

/**
 * @brief Classifies network traffic flows based on hostnames or standard ports.
 * 
 * Provides basic application-layer identification to distinguish services 
 * (e.g., Google, Netflix, HTTPS).
 */
class TrafficClassifier {
public:
    /**
     * @brief Classifies a network flow.
     * 
     * Uses the hostname first for classification via substring matching.
     * Falls back to port-based classification if the hostname is empty or unknown.
     * 
     * @param hostname The extracted hostname from SNI, DNS, or HTTP Host.
     * @param key The flow key containing the source and destination ports.
     * @return A string label representing the classification (e.g., "Google", "HTTPS", "Unknown").
     */
    [[nodiscard]] std::string classify(const std::string& hostname, const FlowKey& key) const;

private:
    /** 
     * @brief Ordered list of hostname substrings to service labels. 
     * More specific entries should come first if there are conflicts.
     */
    const std::vector<std::pair<std::string, std::string>> service_table_ = {
        {"google",     "Google"},
        {"youtube",    "YouTube"},
        {"github",     "GitHub"},
        {"facebook",   "Facebook"},
        {"instagram",  "Instagram"},
        {"netflix",    "Netflix"},
        {"twitter",    "Twitter"},
        {"amazon",     "Amazon"},
        {"discord",    "Discord"},
        {"zoom",       "Zoom"},
        {"cloudflare", "Cloudflare"},
        {"microsoft",  "Microsoft"},
        {"apple",      "Apple"},
        {"spotify",    "Spotify"},
        {"telegram",   "Telegram"},
        {"tiktok",     "TikTok"},
        {"reddit",     "Reddit"},
        {"linkedin",   "LinkedIn"},
        {"dropbox",    "Dropbox"},
        {"twitch",     "Twitch"},
        {"whatsapp",   "WhatsApp"},
        {"slack",      "Slack"},
    };
};

} // namespace PacMan

#endif // PACMAN_TRAFFIC_CLASSIFIER_H
