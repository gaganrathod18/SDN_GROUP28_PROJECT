#pragma once
#include <ftxui/dom/elements.hpp>
#include "../shared_statistics.h"

namespace PacMan {
namespace UI {

    /**
     * @brief Renders a UI component for the dashboard.
     * @return The rendered FTXUI element.
     */
[[nodiscard]] ftxui::Element domainsPanel(const StatsSnapshot& s);
    /**
     * @brief Renders a UI component for the dashboard.
     * @return The rendered FTXUI element.
     */
[[nodiscard]] ftxui::Element talkersPanel(const StatsSnapshot& s);
    /**
     * @brief Renders a UI component for the dashboard.
     * @return The rendered FTXUI element.
     */
[[nodiscard]] ftxui::Element analyticsPanel(const StatsSnapshot& s);

}
}
