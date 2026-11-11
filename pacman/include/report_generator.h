#ifndef PACMAN_REPORT_GENERATOR_H
#define PACMAN_REPORT_GENERATOR_H

#include "pacman_types.h"
#include <string>

namespace PacMan {

/**
 * @brief Generates various reports (Console, CSV, HTML) from the statistics snapshot.
 * 
 * Supports generating reports for both manual exports and live/periodic background tasks.
 * Manual reports go to '<base_dir>/manual/', while live reports go to '<base_dir>/live/'.
 */
class ReportGenerator {
public:
    /**
     * @brief Constructs a generator that writes under the given directory.
     * @param base_dir Parent directory for the 'live/' and 'manual/' report folders.
     */
    explicit ReportGenerator(std::string base_dir = "reports");

    /**
     * @brief Generates a text summary in the console.
     * @param snapshot The current statistics snapshot to summarize.
     * @return True if successful, false otherwise.
     */
    bool generateConsoleSummary(const StatsSnapshot& snapshot) const;
    
    /**
     * @brief Generates a CSV report with flows and alerts.
     * @param snapshot The current statistics snapshot to write.
     * @param is_live If true, saves to 'reports/live/', otherwise to 'reports/manual/'.
     * @return True if successful, false otherwise.
     */
    bool generateCsv(const StatsSnapshot& snapshot, bool is_live) const;
    
    /**
     * @brief Generates a rich HTML report with traffic stats, top domains, and alerts.
     * @param snapshot The current statistics snapshot to write.
     * @param is_live If true, saves to 'reports/live/', otherwise to 'reports/manual/'.
     * @return True if successful, false otherwise.
     */
    bool generateHtml(const StatsSnapshot& snapshot, bool is_live) const;

private:
    /**
     * @brief Helper to generate a timestamped file path.
     * @param extension The file extension (e.g., ".csv", ".html").
     * @param is_live Determines the parent subdirectory (live vs manual).
     * @return The absolute or relative path to the newly generated file name.
     */
    std::string generateTimestampedPath(const std::string& extension, bool is_live) const;

    std::string base_dir_;
};

} // namespace PacMan

#endif // PACMAN_REPORT_GENERATOR_H
