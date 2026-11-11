#pragma once
#include <ftxui/dom/elements.hpp>
#include "../shared_statistics.h"

namespace PacMan {
namespace UI {

    /**
     * @brief Renders a UI component for the dashboard.
     * @return The rendered FTXUI element.
     */
[[nodiscard]] ftxui::Element flowsPanel(const StatsSnapshot& s, std::size_t max_items = 15, int* scroll_y = nullptr);

}
}
