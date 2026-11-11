#include "ui_components/flows_tab.h"
#include "ui_components/common.h"
#include <algorithm>

namespace PacMan {
namespace UI {

using namespace ftxui;

// ---- Recent connections (scrollable last N) --------------------------------
Element flowsPanel(const StatsSnapshot& s, std::size_t max_items, int* scroll_y) {
    Elements rows;
    rows.push_back(
        hbox({
            text("SRC IP")   | size(WIDTH, EQUAL, 17) | bold,
            text("SPORT")    | size(WIDTH, EQUAL, 7)  | bold | color(Color::Orange1),
            text("GEO")      | size(WIDTH, EQUAL, 5)  | bold,
            text("DST IP")   | size(WIDTH, EQUAL, 17) | bold,
            text("DPORT")    | size(WIDTH, EQUAL, 7)  | bold | color(Color::Orange1),
            text("STATE")    | size(WIDTH, EQUAL, 12) | bold,
            text("PROTO")    | size(WIDTH, EQUAL, 7)  | bold,
            text("CLASS")    | size(WIDTH, EQUAL, 13) | bold,
            text("DUR")      | size(WIDTH, EQUAL, 8)  | bold | color(Color::GrayLight),
            text("HOSTNAME") | flex                   | bold,
            text("BYTES")    | size(WIDTH, EQUAL, 10) | bold,
        }) | color(Color::GrayLight)
    );
    rows.push_back(separator());

    const auto& flows = s.recent_flows;
    const std::size_t total = flows.size();
    const std::size_t limit = std::min<std::size_t>(total, max_items);
    
    int max_start = total > limit ? total - limit : 0;
    
    if (scroll_y) {
        if (*scroll_y < 0) *scroll_y = 0;
        if (*scroll_y > max_start) *scroll_y = max_start;
        max_start -= *scroll_y;
    }
    
    const std::size_t start = max_start;

    if (flows.empty()) {
        rows.push_back(text("No connections observed yet") | color(Color::GrayLight));
    }
    for (std::size_t i = start; i < flows.size(); ++i) {
        const Flow& f = flows[i];

        // Session duration
        using namespace std::chrono;
        auto dur_sec = duration_cast<seconds>(f.last_seen - f.first_seen).count();
        std::string dur_str;
        if (dur_sec < 60)        dur_str = std::to_string(dur_sec) + "s";
        else if (dur_sec < 3600) dur_str = std::to_string(dur_sec / 60) + "m";
        else                     dur_str = std::to_string(dur_sec / 3600) + "h";

        // Pick colour for state
        Color stateCol = Color::GrayLight;
        if (f.connection_state.find("ESTAB") != std::string::npos) stateCol = Color::GreenLight;
        else if (f.connection_state.find("SYN") != std::string::npos) stateCol = Color::Yellow;
        else if (f.connection_state.find("FIN") != std::string::npos) stateCol = Color::Red;
        else if (f.connection_state.find("RST") != std::string::npos) stateCol = Color::RedLight;

        rows.push_back(hbox({
            text(truncate(f.key.src_ip, 15))       | size(WIDTH, EQUAL, 17) | color(Color::White),
            text(std::to_string(f.key.src_port))   | size(WIDTH, EQUAL, 7)  | color(Color::Orange1),
            text(f.dst_country)                    | size(WIDTH, EQUAL, 5)  | color(Color::CyanLight),
            text(truncate(f.key.dst_ip, 15))       | size(WIDTH, EQUAL, 17) | color(Color::White),
            text(std::to_string(f.key.dst_port))   | size(WIDTH, EQUAL, 7)  | color(Color::Orange1),
            text(f.connection_state)               | size(WIDTH, EQUAL, 12) | color(stateCol),
            text(protocolToString(f.key.protocol)) | size(WIDTH, EQUAL, 7)  | color(Color::Yellow),
            text(truncate(f.classification, 11))   | size(WIDTH, EQUAL, 13) | color(classColor(f.classification)),
            text(dur_str)                          | size(WIDTH, EQUAL, 8)  | color(Color::GrayLight),
            text(truncate(f.hostname, 28))         | flex                   | color(Color::CyanLight),
            text(fmtBytes(f.bytes))                | size(WIDTH, EQUAL, 10) | color(Color::GreenLight),
        }));
    }
    return vbox(rows) | border | flex;
}

}
}
