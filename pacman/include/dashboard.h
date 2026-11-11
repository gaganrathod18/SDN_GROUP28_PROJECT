#ifndef PACMAN_DASHBOARD_H
#define PACMAN_DASHBOARD_H

#include "config_manager.h"
#include "shared_statistics.h"
#include <atomic>

namespace PacMan {

/**
 * @brief Terminal-based dashboard for displaying live network statistics.
 * 
 * Uses FTXUI (if enabled) for a rich interactive terminal UI, or falls back to
 * a simple plain-text logging view.
 */
class Dashboard {
public:
    /**
     * @brief Constructs the Dashboard.
     * @param config The application configuration.
     * @param statistics The shared statistics object.
     */
    Dashboard(const Config& config, const SharedStatistics& statistics);

    /**
     * @brief Runs the UI loop until `running` is set to false.
     * @param running Atomic flag to control the loop.
     */
    void run(std::atomic<bool>& running);

private:
    Config config_;
    const SharedStatistics& statistics_;

    /**
     * @brief Draws the plain-text fallback dashboard.
     * @param snapshot The current statistics snapshot.
     */
    void drawPlain(const StatsSnapshot& snapshot) const;
};

} // namespace PacMan

#endif // PACMAN_DASHBOARD_H
