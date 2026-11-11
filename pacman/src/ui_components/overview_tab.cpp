#include "ui_components/overview_tab.h"
#include "ui_components/common.h"
#include "ui_components/flows_tab.h"
#include "ui_components/ids_tab.h"
#include <algorithm>
#include <vector>

namespace PacMan {
namespace UI {

using namespace ftxui;

// ---- Protocol mix bar rows -------------------------------------------------
Element protocolPanel(const StatsSnapshot& s) {
    Elements rows;
    rows.push_back(text(" Protocol Mix") | bold | color(Color::BlueLight));
    rows.push_back(separator());

    const std::uint64_t total = s.total_packets > 0 ? s.total_packets : 1;
    struct Entry { std::string label; std::uint64_t n; Color col; };
    std::vector<Entry> entries = {
        {"TCP  ", s.tcp_packets,   Color::CyanLight},
        {"UDP  ", s.udp_packets,   Color::Yellow},
        {"Other", s.other_packets, Color::GrayLight},
    };
    for (const auto& e : entries) {
        const float pct = static_cast<float>(e.n) / static_cast<float>(total);
        rows.push_back(hbox({
            text(e.label) | color(e.col) | size(WIDTH, EQUAL, 6),
            gauge(pct)    | color(e.col) | flex,
            text(" " + fmtPkts(e.n)) | size(WIDTH, EQUAL, 7),
        }));
    }
    return vbox(rows) | border;
}

// ---- Traffic breakdown bar chart -------------------------------------------
Element trafficPanel(const StatsSnapshot& s) {
    Elements rows;
    rows.push_back(text(" Traffic by Class") | bold | color(Color::BlueLight));
    rows.push_back(separator());

    if (s.traffic_by_class.empty()) {
        rows.push_back(text("No classified traffic yet") | color(Color::GrayLight));
        return vbox(rows) | border | flex;
    }

    std::uint64_t max_bytes = 1;
    for (const auto& e : s.traffic_by_class)
        max_bytes = std::max(max_bytes, e.second);

    std::vector<std::pair<std::string, std::uint64_t>> sorted(
        s.traffic_by_class.begin(), s.traffic_by_class.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    const std::size_t limit = std::min<std::size_t>(sorted.size(), 8);
    for (std::size_t i = 0; i < limit; ++i) {
        const float pct = static_cast<float>(sorted[i].second) / static_cast<float>(max_bytes);
        rows.push_back(hbox({
            text(truncate(sorted[i].first, 12)) | size(WIDTH, EQUAL, 13) | color(classColor(sorted[i].first)),
            gauge(pct) | color(classColor(sorted[i].first)) | flex,
            text(" " + fmtBytes(sorted[i].second)) | size(WIDTH, EQUAL, 10),
        }));
    }
    return vbox(rows) | border | flex;
}

// ---- Live Bandwidth Sparkline (60-sample rolling graph) ---------------------
Element bandwidthPanel(const std::vector<double>& bw_history,
                       const std::vector<double>& pps_history,
                       int height,
                       const std::string& legend_time) {
    Elements rows;
    rows.push_back(hbox({
        text(" ▲ Live Bandwidth") | bold | color(Color::BlueLight),
        filler(),
        text(bw_history.empty() ? "—" : fmtBytesRate(bw_history.back()))
            | bold | color(Color::GreenLight),
        text("  "),
    }));
    rows.push_back(separator());

    // Normalise bandwidth samples for the graph callback
    const double max_bw = bw_history.empty() ? 1.0
        : *std::max_element(bw_history.begin(), bw_history.end());
    const double safe_max = max_bw > 0.0 ? max_bw : 1.0;

    auto bw_graph = graph([&bw_history, safe_max](int w, int h) {
        std::vector<int> out(static_cast<std::size_t>(w), 0);
        const std::size_t n = bw_history.size();
        for (int col = 0; col < w; ++col) {
            const int sample_idx = static_cast<int>(n) - w + col;
            if (sample_idx >= 0 && sample_idx < static_cast<int>(n)) {
                out[static_cast<std::size_t>(col)] =
                    static_cast<int>((bw_history[static_cast<std::size_t>(sample_idx)] / safe_max)
                                     * static_cast<double>(h));
            }
        }
        return out;
    }) | color(Color::GreenLight) | flex;

    // Normalise pps samples
    const double max_pps = pps_history.empty() ? 1.0
        : *std::max_element(pps_history.begin(), pps_history.end());
    const double safe_max_pps = max_pps > 0.0 ? max_pps : 1.0;

    auto pps_graph = graph([&pps_history, safe_max_pps](int w, int h) {
        std::vector<int> out(static_cast<std::size_t>(w), 0);
        const std::size_t n = pps_history.size();
        for (int col = 0; col < w; ++col) {
            const int sample_idx = static_cast<int>(n) - w + col;
            if (sample_idx >= 0 && sample_idx < static_cast<int>(n)) {
                out[static_cast<std::size_t>(col)] =
                    static_cast<int>((pps_history[static_cast<std::size_t>(sample_idx)] / safe_max_pps)
                                     * static_cast<double>(h));
            }
        }
        return out;
    }) | color(Color::Yellow) | flex;

    rows.push_back(hbox({
        vbox({
            text(fmtBytesRate(safe_max)) | color(Color::GrayLight),
            filler(),
            text("0 B/s") | color(Color::GrayLight),
        }) | size(WIDTH, EQUAL, 10),
        bw_graph,
    }) | size(HEIGHT, EQUAL, height) | flex);

    rows.push_back(separatorLight());

    rows.push_back(hbox({
        vbox({
            text(fmtPkts(static_cast<std::uint64_t>(safe_max_pps)) + " pps") | color(Color::GrayLight),
            filler(),
            text("0 pps") | color(Color::GrayLight),
        }) | size(WIDTH, EQUAL, 10),
        pps_graph,
    }) | size(HEIGHT, EQUAL, height) | flex);

    rows.push_back(separator());
    rows.push_back(hbox({
        text("  Y-Axis auto-scales to local peak | X-Axis = " + legend_time)
            | color(Color::GrayLight),
        filler(),
        text("Bandwidth ") | color(Color::GreenLight) | bold,
        text("Packets/s ") | color(Color::Yellow) | bold,
    }));

    return vbox(rows) | border | flex;
}

// ---- Compact Recent Flows (for Overview) -----------------------------------
Element recentFlowsCompact(const StatsSnapshot& s) {
    Elements rows;
    rows.push_back(hbox({
        text(" Recent Flows") | bold | color(Color::BlueLight),
        filler(),
        text(std::to_string(s.recent_flows.size()) + " total ") | color(Color::GrayLight),
    }));
    rows.push_back(separator());
    rows.push_back(hbox({
        text("SRC IP")   | size(WIDTH, EQUAL, 17) | bold | color(Color::GrayLight),
        text("→ DST IP") | size(WIDTH, EQUAL, 18) | bold | color(Color::GrayLight),
        text("PORT")     | size(WIDTH, EQUAL, 7)  | bold | color(Color::GrayLight),
        text("PROTO")    | size(WIDTH, EQUAL, 6)  | bold | color(Color::GrayLight),
        text("STATE")    | size(WIDTH, EQUAL, 12) | bold | color(Color::GrayLight),
        text("BYTES")    | size(WIDTH, EQUAL, 10) | bold | color(Color::GrayLight),
        text("HOSTNAME") | flex                   | bold | color(Color::GrayLight),
    }));
    rows.push_back(separatorLight());

    const auto& flows = s.recent_flows;
    if (flows.empty()) {
        rows.push_back(text("  No connections yet") | color(Color::GrayLight));
    } else {
        // Show last 8 flows
        const std::size_t limit = std::min<std::size_t>(flows.size(), 8);
        const std::size_t start = flows.size() - limit;
        for (std::size_t i = start; i < flows.size(); ++i) {
            const Flow& f = flows[i];
            const std::string proto = (f.key.protocol == Protocol::TCP) ? "TCP"
                                   : (f.key.protocol == Protocol::UDP) ? "UDP" : "OTH";
            Color stateCol = Color::GrayLight;
            if (f.connection_state.find("ESTAB") != std::string::npos) stateCol = Color::GreenLight;
            else if (f.connection_state.find("TIME_WAIT") != std::string::npos) stateCol = Color::Yellow;
            else if (f.connection_state.find("SYN") != std::string::npos) stateCol = Color::CyanLight;

            rows.push_back(hbox({
                text(f.key.src_ip)  | size(WIDTH, EQUAL, 17) | color(Color::White),
                text("→ " + f.key.dst_ip) | size(WIDTH, EQUAL, 18) | color(Color::CyanLight),
                text(std::to_string(f.key.dst_port)) | size(WIDTH, EQUAL, 7)  | color(Color::Orange1),
                text(proto)         | size(WIDTH, EQUAL, 6)  | color(Color::Yellow),
                text(f.connection_state) | size(WIDTH, EQUAL, 12) | color(stateCol),
                text(fmtBytes(f.bytes)) | size(WIDTH, EQUAL, 10) | color(Color::White),
                text(f.hostname.empty() ? "—" : f.hostname) | flex | color(Color::GrayLight),
            }));
        }
    }
    return vbox(rows) | border | size(HEIGHT, EQUAL, 13);
}

Element overviewPanel(const StatsSnapshot& s, 
                      const std::vector<double>& bw_history, 
                      const std::vector<double>& pps_history) {
    // Top row: Protocol Mix (narrow) + Traffic by Class (flex)
    auto top = hbox({
        protocolPanel(s) | size(WIDTH, EQUAL, 46),
        trafficPanel(s) | flex
    });

    // Middle: 50% bandwidth sparkline | 50% live alerts panel
    auto middle = hbox({
        bandwidthPanel(bw_history, pps_history, 3) | flex,
        alertsMiniPanel(s) | flex,
    }) | size(HEIGHT, EQUAL, 20);

    // Bottom: Recent flows table
    auto bottom = recentFlowsCompact(s);

    return vbox({
        top,
        middle,
        bottom
    }) | flex;
}

} // namespace UI
} // namespace PacMan
