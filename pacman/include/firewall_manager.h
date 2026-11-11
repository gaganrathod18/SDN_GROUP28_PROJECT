#ifndef PACMAN_FIREWALL_MANAGER_H
#define PACMAN_FIREWALL_MANAGER_H

#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include "pacman_types.h"

namespace PacMan {

/**
 * @brief Manages system-level firewall rules to block malicious traffic.
 * 
 * Passive mode only records rules (no system changes). SDN mode appends each block request
 * to a blocklist file that the SDN controller reads and turns into OpenFlow drop rules.
 */
class FirewallManager {
public:
    /**
     * @brief Constructs a new Firewall Manager and initializes state.
     */
    FirewallManager();
    
    /**
     * @brief Destructor. Cleans up firewall state and releases resources.
     */
    ~FirewallManager();

    // Disable copy/move due to system state modifications (which act as singletons conceptually)
    FirewallManager(const FirewallManager&) = delete;
    FirewallManager& operator=(const FirewallManager&) = delete;

    /**
     * @brief Initializes the firewall manager.
     */
    void initialize();
    
    /**
     * @brief Tears down the firewall manager, clearing all active rules.
     */
    void teardown();

    /**
     * @brief Selects passive or SDN mode.
     * @param mode "passive" or "sdn".
     * @param blocklist_file File the controller reads (SDN mode).
     * @param cooldown_s Minimum seconds between two requests for the same IP.
     */
    void configure(const std::string& mode, const std::string& blocklist_file, std::uint64_t cooldown_s);

    /**
     * @brief Dynamically block an IP address.
     * @param ip The IP address to block.
     * @param reason The reason for the block.
     * @return True if a new request was written to the blocklist (SDN mode only).
     */
    bool blockIp(const std::string& ip, const std::string& reason);

    /**
     * @brief Error text of the last failed blocklist write (empty if none).
     */
    [[nodiscard]] std::string lastError() const;

    /**
     * @brief Gets a snapshot of the currently active firewall rules.
     * @return A vector of active FirewallRule structures.
     */
    [[nodiscard]] std::vector<FirewallRule> getActiveRules() const;

private:
    void runCommand(const std::string& cmd);
    
    [[nodiscard]] bool checkRoot();

    mutable std::mutex mutex_;
    std::vector<FirewallRule> rules_;
    bool initialized_{false};
    bool sdn_mode_{false};
    std::string blocklist_file_;
    std::chrono::seconds cooldown_{30};
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_request_;
    std::string last_error_;
};

} // namespace PacMan

#endif // PACMAN_FIREWALL_MANAGER_H
