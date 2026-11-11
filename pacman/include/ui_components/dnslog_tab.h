#pragma once
#include <ftxui/dom/elements.hpp>
#include "../shared_statistics.h"

namespace PacMan {
namespace UI {

    /**
     * @brief Renders a UI component for the dashboard.
     * @return The rendered FTXUI element.
     */
[[nodiscard]] ftxui::Element dnsLogPanel(const StatsSnapshot& s);

}
}
