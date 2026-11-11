#include "ui_components/traffic_tab.h"
#include "ui_components/common.h"
#include <algorithm>

namespace PacMan {
namespace UI {

using namespace ftxui;

Element trafficGraphPanel(const std::vector<double>& bw_history,
                          const std::vector<double>& pps_history) {
    // ---- Compute stats ----
    const double cur_bw  = bw_history.empty()  ? 0.0 : bw_history.back();
    const double cur_pps = pps_history.empty() ? 0.0 : pps_history.back();

    double peak_bw = 1.0, sum_bw = 0.0;
    for (double v : bw_history)  { peak_bw = std::max(peak_bw, v); sum_bw += v; }
    double avg_bw = bw_history.empty() ? 0.0 : sum_bw / bw_history.size();

    double peak_pps = 1.0, sum_pps = 0.0;
    for (double v : pps_history) { peak_pps = std::max(peak_pps, v); sum_pps += v; }
    double avg_pps = pps_history.empty() ? 0.0 : sum_pps / pps_history.size();

    const double safe_bw  = peak_bw  > 0 ? peak_bw  : 1.0;
    const double safe_pps = peak_pps > 0 ? peak_pps : 1.0;

    // ---- BW graph with Y-axis labels ----
    auto bw_graph = graph([&bw_history, safe_bw](int w, int h) {
        std::vector<int> out(static_cast<std::size_t>(w), 0);
        const std::size_t n = bw_history.size();
        for (int col = 0; col < w; ++col) {
            int idx = static_cast<int>(n) - w + col;
            if (idx >= 0 && idx < static_cast<int>(n))
                out[static_cast<std::size_t>(col)] =
                    static_cast<int>((bw_history[static_cast<std::size_t>(idx)] / safe_bw) * h);
        }
        return out;
    }) | color(Color::GreenLight) | flex;

    auto pps_graph = graph([&pps_history, safe_pps](int w, int h) {
        std::vector<int> out(static_cast<std::size_t>(w), 0);
        const std::size_t n = pps_history.size();
        for (int col = 0; col < w; ++col) {
            int idx = static_cast<int>(n) - w + col;
            if (idx >= 0 && idx < static_cast<int>(n))
                out[static_cast<std::size_t>(col)] =
                    static_cast<int>((pps_history[static_cast<std::size_t>(idx)] / safe_pps) * h);
        }
        return out;
    }) | color(Color::Yellow) | flex;

    // ---- Y-axis label column (BW) ----
    auto bw_yaxis = vbox({
        text(fmtBytesRate(peak_bw) + " ┤")        | color(Color::GreenLight),
        filler(),
        text(fmtBytesRate(peak_bw * 0.75) + " ┤") | color(Color::GreenLight),
        filler(),
        text(fmtBytesRate(peak_bw * 0.50) + " ┤") | color(Color::GreenLight),
        filler(),
        text(fmtBytesRate(peak_bw * 0.25) + " ┤") | color(Color::GreenLight),
        filler(),
        text("0 B/s ┤")                      | color(Color::GrayLight),
    }) | size(WIDTH, EQUAL, 13);

    // ---- Y-axis label column (PPS) ----
    auto pps_yaxis = vbox({
        text(fmtPkts(static_cast<std::uint64_t>(peak_pps)) + "/s ┤")        | color(Color::Yellow),
        filler(),
        text(fmtPkts(static_cast<std::uint64_t>(peak_pps * 0.75)) + "/s ┤") | color(Color::Yellow),
        filler(),
        text(fmtPkts(static_cast<std::uint64_t>(peak_pps * 0.50)) + "/s ┤") | color(Color::Yellow),
        filler(),
        text(fmtPkts(static_cast<std::uint64_t>(peak_pps * 0.25)) + "/s ┤") | color(Color::Yellow),
        filler(),
        text("0 ┤")                                                           | color(Color::GrayLight),
    }) | size(WIDTH, EQUAL, 13);

    // ---- Stats sidebar ----
    auto stats_col = vbox({
        text("  BW Stats") | bold | color(Color::GreenLight),
        separatorLight(),
        hbox({ text("  Now  : ") | color(Color::GrayLight), text(fmtBytesRate(cur_bw))  | bold | color(Color::White)  }),
        hbox({ text("  Avg  : ") | color(Color::GrayLight), text(fmtBytesRate(avg_bw))  | bold | color(Color::GreenLight) }),
        hbox({ text("  Peak : ") | color(Color::GrayLight), text(fmtBytesRate(peak_bw)) | bold | color(Color::GreenLight) }),
        text(""),
        text("  PPS Stats") | bold | color(Color::Yellow),
        separatorLight(),
        hbox({ text("  Now  : ") | color(Color::GrayLight), text(fmtPkts(static_cast<std::uint64_t>(cur_pps))  + "/s") | bold | color(Color::White)  }),
        hbox({ text("  Avg  : ") | color(Color::GrayLight), text(fmtPkts(static_cast<std::uint64_t>(avg_pps))  + "/s") | bold | color(Color::Yellow) }),
        hbox({ text("  Peak : ") | color(Color::GrayLight), text(fmtPkts(static_cast<std::uint64_t>(peak_pps)) + "/s") | bold | color(Color::Yellow) }),
        text(""),
        text("  Window") | bold | color(Color::GrayLight),
        separatorLight(),
        text("  300 seconds") | color(Color::GrayLight),
        text("  1 sample/sec") | color(Color::GrayLight),
        filler(),
    }) | border | size(WIDTH, EQUAL, 24);

    // ---- Time axis below graph ----
    auto time_axis = hbox({
        text("") | size(WIDTH, EQUAL, 13),  // Y-axis gutter
        text("┬ -300s") | color(Color::GrayLight),
        filler(),
        text("┬ -225s") | color(Color::GrayLight),
        filler(),
        text("┬ -150s") | color(Color::GrayLight),
        filler(),
        text("┬ -75s")  | color(Color::GrayLight),
        filler(),
        text("┬ now")   | color(Color::GreenLight) | bold,
    });

    auto make_grid = []() {
        return vbox({
            filler(),
            separatorLight() | color(Color::GrayLight),
            filler(),
            separatorLight() | color(Color::GrayLight),
            filler(),
            separatorLight() | color(Color::GrayLight),
            filler(),
            separatorLight() | color(Color::GrayLight),
            filler(),
        }) | flex;
    };

    auto bw_panel = vbox({
        text(" Bandwidth  (B/s)") | bold | color(Color::GreenLight),
        separator(),
        hbox({ 
            bw_yaxis, 
            dbox({ make_grid(), bw_graph | flex }) | flex 
        }) | flex,
        separatorLight(),
        time_axis,
    }) | border | flex;

    auto pps_panel = vbox({
        text(" Packets/sec") | bold | color(Color::Yellow),
        separator(),
        hbox({ 
            pps_yaxis, 
            dbox({ make_grid(), pps_graph | flex }) | flex 
        }) | flex,
        separatorLight(),
        time_axis,
    }) | border | flex;

    return hbox({
        vbox({ bw_panel, pps_panel }) | flex,
        stats_col,
    }) | flex;
}

}
}
