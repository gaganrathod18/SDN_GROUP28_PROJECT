#ifndef PACMAN_CONFIG_MANAGER_H
#define PACMAN_CONFIG_MANAGER_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace PacMan {

/**
 * @brief Application configuration options loaded from the pacman.conf file.
 */
struct Config {
    std::string interface_name = "any";               ///< Network interface to capture packets on
    std::string reports_dir = "reports";               ///< Directory to save generated reports in
    std::string log_file = "logs/pacman.log";          ///< File path for storing application logs
    std::string virus_total_api_key;                   ///< Optional API Key for VirusTotal domain checks
    int refresh_ms = 400;                              ///< Refresh rate of the TUI Dashboard in milliseconds
    std::size_t queue_size = 10000;                    ///< Maximum size of the ThreadSafeQueue packet buffer
    std::uint64_t high_connection_threshold = 50;      ///< Maximum single-source flows before warning
    std::uint64_t port_scan_threshold = 15;            ///< Maximum unique target ports probed before warning
    std::uint64_t large_transfer_bytes = 50ULL * 1024ULL * 1024ULL; ///< Size threshold for large transfer alarm
    std::uint64_t detection_window_s = 10;             ///< Sliding window for scan / flood counting (seconds)
    std::uint64_t syn_flood_threshold = 200;           ///< New TCP connections from one source per window before a HIGH alert
    std::string firewall_mode = "passive";             ///< "passive" (record only) or "sdn" (write blocklist for the SDN controller)
    std::string blocklist_file = "blocklist.txt";      ///< File the SDN controller reads attacker IPs from (sdn mode)
    std::uint64_t block_cooldown_s = 30;
    std::string detector_mode = "initiated";           ///< "initiated" (count only connections a host opens) or "naive" (every new flow; for comparison)               ///< Minimum seconds between two block requests for the same IP
};

/**
 * @brief Loader and manager class for the application configuration file.
 */
class ConfigManager {
public:
    /**
     * @brief Load configurations from a custom configuration file path.
     * @param config_file_path System file path to configuration settings.
     * @return true if loaded successfully, false otherwise.
     */
    bool load(const std::string& config_file_path);

    /**
     * @brief Access the currently active configuration settings.
     */
    [[nodiscard]] const Config& config() const { return config_; }

private:
    Config config_; ///< The loaded configuration parameters

    /**
     * @brief Parse a single configuration property line key-value pair.
     */
    void applyValue(const std::string& key, const std::string& value);
    void applyValueChecked(const std::string& key, const std::string& value);
};

} // namespace PacMan

#endif // PACMAN_CONFIG_MANAGER_H
