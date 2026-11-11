#include "ui_components/protocols_tab.h"
#include "ui_components/common.h"
#include <algorithm>

namespace PacMan {
namespace UI {

using namespace ftxui;

Element protocolsPanel(const StatsSnapshot& s) {
    Elements rows;

    // Sort first so we have count + total for the title
    std::vector<std::pair<std::string, std::uint64_t>> sorted(
        s.traffic_by_class.begin(), s.traffic_by_class.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    std::uint64_t total_bytes = 0;
    std::uint64_t max_bytes   = 1;
    for (const auto& e : sorted) {
        total_bytes += e.second;
        max_bytes    = std::max(max_bytes, e.second);
    }

    // Title with stats on the right
    rows.push_back(hbox({
        text(" Protocol Distribution") | bold | color(Color::BlueLight),
        filler(),
        text(std::to_string(sorted.size()) + " protocols  ") | bold | color(Color::GreenLight),
        text(fmtBytes(total_bytes) + " total ") | color(Color::GrayLight),
    }));
    rows.push_back(separator());

    // Column header
    rows.push_back(hbox({
        text("#")        | size(WIDTH, EQUAL, 4)  | bold | color(Color::GrayLight),
        text("PROTOCOL") | size(WIDTH, EQUAL, 16) | bold | color(Color::GrayLight),
        text("TRAFFIC")  | flex                   | bold | color(Color::GrayLight),
        text(" %   ")    | size(WIDTH, EQUAL, 8)  | bold | color(Color::GrayLight),
        text("BYTES")    | size(WIDTH, EQUAL, 14) | bold | color(Color::GrayLight),
    }));
    rows.push_back(separator());

    // Color palette cycling for gauge bars
    const Color palette[] = {
        Color::CyanLight, Color::GreenLight, Color::Yellow,
        Color::BlueLight, Color::Magenta,    Color::RedLight,
    };

    if (sorted.empty()) {
        rows.push_back(text("  No classified traffic yet") | color(Color::GrayLight));
    }

    int rank = 1;
    for (const auto& p : sorted) {
        const float pct    = static_cast<float>(p.second) / static_cast<float>(max_bytes);
        const float pct100 = total_bytes > 0
            ? 100.0f * p.second / total_bytes : 0.0f;

        char pct_buf[12];
        std::snprintf(pct_buf, sizeof(pct_buf), "%5.1f%%", pct100);

        const Color bar_col = palette[(rank - 1) % 6];

        rows.push_back(hbox({
            text(std::to_string(rank) + " ")              | size(WIDTH, EQUAL, 4)  | color(Color::GrayLight),
            text(truncate(p.first, 15))                   | size(WIDTH, EQUAL, 16) | color(bar_col) | bold,
            gauge(pct)                                    | flex                   | color(bar_col),
            text(pct_buf)                                 | size(WIDTH, EQUAL, 8)  | color(Color::GrayLight),
            text(" " + fmtBytes(p.second))                | size(WIDTH, EQUAL, 14) | color(Color::White),
        }));
        rows.push_back(separatorLight() | color(Color::GrayLight));
        ++rank;
    }

    // Footer — gauge scale note
    rows.push_back(separator());
    rows.push_back(
        text("  Gauge scaled to highest-traffic protocol  ") | color(Color::GrayLight)
    );

    return vbox(rows) | border | flex;
}

}
}
