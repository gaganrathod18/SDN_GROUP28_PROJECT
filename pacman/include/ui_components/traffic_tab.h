#pragma once
#include <ftxui/dom/elements.hpp>
#include <vector>

namespace PacMan {
namespace UI {

    /**
     * @brief Renders a UI component for the dashboard.
     * @return The rendered FTXUI element.
     */
[[nodiscard]] ftxui::Element trafficGraphPanel(const std::vector<double>& bw_history,
                                 const std::vector<double>& pps_history);

}
}
