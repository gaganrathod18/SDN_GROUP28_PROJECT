#include "ui_components/endpoints_tab.h"
#include "ui_components/common.h"
#include <algorithm>
#include <map>
#include <set>
#include <vector>

namespace PacMan {
namespace UI {

using namespace ftxui;

Element endpointsPanel(const StatsSnapshot& s) {
    Elements rows;

    // Build data first so we can show count in the title
    std::map<std::string, std::vector<std::string>> matrix;
    std::map<std::string, std::set<uint16_t>>       port_scan_tracker;
    for (const auto& f : s.recent_flows) {
        matrix[f.key.src_ip].push_back(f.key.dst_ip);
        port_scan_tracker[f.key.src_ip].insert(f.key.dst_port);
    }

    // Title with count on the right
    rows.push_back(hbox({
        text(" Endpoint Connection Matrix") | bold | color(Color::CyanLight),
        filler(),
        text("Endpoints: ") | color(Color::GrayLight),
        text(std::to_string(matrix.size())) | bold | color(Color::GreenLight),
        text(" "),
    }));
    rows.push_back(separator());

    // Column header
    rows.push_back(hbox({
        text("   ")          | size(WIDTH, EQUAL, 4),
        text("SOURCE IP")    | size(WIDTH, EQUAL, 19) | bold | color(Color::GrayLight),
        text("CONNS")        | size(WIDTH, EQUAL, 8)  | bold | color(Color::GrayLight),
        text("PORTS")        | size(WIDTH, EQUAL, 8)  | bold | color(Color::GrayLight),
        text("DESTINATIONS") | flex                   | bold | color(Color::GrayLight),
    }));
    rows.push_back(separator());

    if (matrix.empty()) {
        rows.push_back(text("  No connection data yet") | color(Color::GrayLight));
    }


    for (auto& kv : matrix) {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());

        const bool is_scanner = port_scan_tracker[kv.first].size() >= 10;
        const std::size_t port_count = port_scan_tracker[kv.first].size();
        const std::size_t conn_count = kv.second.size();

        // Build compact dest list: show first 4, then "+N more"
        std::string dest_str;
        const std::size_t show = std::min<std::size_t>(kv.second.size(), 4);
        for (std::size_t i = 0; i < show; ++i) {
            if (i > 0) dest_str += "  ";
            dest_str += truncate(kv.second[i], 15);
        }
        if (kv.second.size() > show)
            dest_str += "  +" + std::to_string(kv.second.size() - show) + " more";

        rows.push_back(hbox({
            text(is_scanner ? "[!]" : "   ") | size(WIDTH, EQUAL, 4) | bold | color(is_scanner ? Color::Red : Color::GrayLight),
            text(truncate(kv.first, 18))     | size(WIDTH, EQUAL, 19) | color(Color::White),
            text(std::to_string(conn_count)) | size(WIDTH, EQUAL, 8)  | color(Color::CyanLight),
            text(std::to_string(port_count)) | size(WIDTH, EQUAL, 8)  | color(is_scanner ? Color::Red : Color::GrayLight),
            text(dest_str)                   | flex                   | color(Color::GrayLight),
        }));
        rows.push_back(separatorLight() | color(Color::GrayLight));
    }

    // Footer legend
    rows.push_back(separator());
    rows.push_back(
        text("  Legend: [!] = Potential port scanner (>10 unique ports) ") | color(Color::GrayLight)
    );

    return vbox(rows) | border | flex;
}

}
}
