#pragma once

#include <ftxui/dom/elements.hpp>
#include "../shared_statistics.h"

namespace PacMan {
namespace UI {

    /**
     * @brief Renders a UI component for the dashboard.
     * @return The rendered FTXUI element.
     */
[[nodiscard]] ftxui::Element protocolPanel(const StatsSnapshot& s);
    /**
     * @brief Renders a UI component for the dashboard.
     * @return The rendered FTXUI element.
     */
[[nodiscard]] ftxui::Element trafficPanel(const StatsSnapshot& s);
    /**
     * @brief Renders a UI component for the dashboard.
     * @return The rendered FTXUI element.
     */
[[nodiscard]] ftxui::Element bandwidthPanel(const std::vector<double>& bw_history,
                              const std::vector<double>& pps_history,
                              int height = 3,
                              const std::string& legend_time = "60s window ");

    /**
     * @brief Renders a UI component for the dashboard.
     * @return The rendered FTXUI element.
     */
[[nodiscard]] ftxui::Element overviewPanel(const StatsSnapshot& s, 
                             const std::vector<double>& bw_history, 
                             const std::vector<double>& pps_history);

} // namespace UI
} // namespace PacMan
