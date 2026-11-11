#include "dashboard.h"
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

#if defined(PACMAN_HAVE_FTXUI)
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
using namespace ftxui;
#include "ui_components/overview_tab.h"
#include "ui_components/flows_tab.h"
#include "ui_components/dnslog_tab.h"
#include "ui_components/traffic_tab.h"
#include "ui_components/protocols_tab.h"
#include "ui_components/endpoints_tab.h"
#include "ui_components/analytics_tab.h"
#include "ui_components/help_tab.h"
#include "ui_components/firewall_tab.h"
#include "ui_components/ips_tab.h"
#include "ui_components/ids_tab.h"
#include "ui_components/crypto_tab.h"
#include "ui_components/common.h"
#endif

namespace PacMan {

// ============================================================================
// Shared helpers (used by both FTXUI and plain builds)
// ============================================================================

namespace {

std::string fallback_fmtBytes(std::uint64_t bytes) {
    std::ostringstream ss;
    if (bytes >= 1024ULL * 1024ULL * 1024ULL)
        ss << std::fixed << std::setprecision(1) << (bytes / (1024.0 * 1024.0 * 1024.0)) << " GB";
    else if (bytes >= 1024ULL * 1024ULL)
        ss << std::fixed << std::setprecision(1) << (bytes / (1024.0 * 1024.0)) << " MB";
    else if (bytes >= 1024ULL)
        ss << std::fixed << std::setprecision(1) << (bytes / 1024.0) << " KB";
    else
        ss << bytes << " B";
    return ss.str();
}

std::string fallback_fmtBytesRate(double bps) {
    std::ostringstream ss;
    if (bps >= 1024.0 * 1024.0 * 1024.0)
        ss << std::fixed << std::setprecision(1) << (bps / (1024.0 * 1024.0 * 1024.0)) << " GB/s";
    else if (bps >= 1024.0 * 1024.0)
        ss << std::fixed << std::setprecision(1) << (bps / (1024.0 * 1024.0)) << " MB/s";
    else if (bps >= 1024.0)
        ss << std::fixed << std::setprecision(1) << (bps / 1024.0) << " KB/s";
    else
        ss << static_cast<std::uint64_t>(bps) << " B/s";
    return ss.str();
}

std::string fallback_fmtPkts(std::uint64_t n) {
    if (n >= 1'000'000) return std::to_string(n / 1'000'000) + "M";
    if (n >= 1'000)     return std::to_string(n / 1'000) + "K";
    return std::to_string(n);
}

} // namespace

// ============================================================================
// ============================================================================
// Dashboard::run  (FTXUI path)
// ============================================================================

#if defined(PACMAN_HAVE_FTXUI)
using namespace PacMan::UI;


Dashboard::Dashboard(const Config& config, const SharedStatistics& statistics)
    : config_(config), statistics_(statistics) {}

void Dashboard::run(std::atomic<bool>& running) {
    auto screen = ScreenInteractive::Fullscreen();

    // Rolling 60-sample history for the live bandwidth sparkline
    std::vector<double> bw_history;
    std::vector<double> pps_history;
    bw_history.reserve(60);
    pps_history.reserve(60);

    std::vector<double> long_bw_history;
    std::vector<double> long_pps_history;
    long_bw_history.reserve(300);
    long_pps_history.reserve(300);

    int tab_selected = 0;
    int flows_scroll_y = 0;
    std::vector<std::string> tab_entries = {
        "Overview",    // 0  — bird's eye: metrics, BW, alerts, flows
        "Flows",       // 1  — full connection table
        "Alerts",      // 2  — dedicated alert feed (new!)
        "DNS",         // 3  — DNS query log
        "Protocols",   // 4  — protocol breakdown
        "Endpoints",   // 5  — IP/endpoint matrix
        "Traffic",     // 6  — long-window BW graph
        "Analytics",   // 7  — top domains & talkers
        "Firewall",    // 8  — iptables rule matrix
        "IPS",         // 9  — IPS actions
        "IDS",         // 10 — IDS detection engine
        "Crypto",      // 11 — TLS/cipher analysis
        "Help"         // 12 — keybindings
    };
    auto tab_toggle = Toggle(&tab_entries, &tab_selected);

    // Build the full-screen component that re-renders every tick.
    auto renderer = Renderer(tab_toggle, [&] {
        const StatsSnapshot s = statistics_.snapshot();

        // Update bandwidth history (capped at 60 samples)
        bw_history.push_back(s.bytes_per_sec);
        if (bw_history.size() > 60) bw_history.erase(bw_history.begin());
        pps_history.push_back(s.packets_per_sec);
        if (pps_history.size() > 60) pps_history.erase(pps_history.begin());

        long_bw_history.push_back(s.bytes_per_sec);
        if (long_bw_history.size() > 300) long_bw_history.erase(long_bw_history.begin());
        long_pps_history.push_back(s.packets_per_sec);
        if (long_pps_history.size() > 300) long_pps_history.erase(long_pps_history.begin());

        // Header bar --------------------------------------------------------
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        std::tm now_tm;
        localtime_r(&now_c, &now_tm);
        char time_buf[64];
        std::snprintf(time_buf, sizeof(time_buf), "%02d:%02d:%02d:%03d",
                      now_tm.tm_hour, now_tm.tm_min, now_tm.tm_sec, static_cast<int>(ms.count()));

        auto header = hbox({
            text(" "),
            text("PacMan") | bold | color(Color::GreenLight),
            text("  Packet Analysis & Cyber Monitoring") | color(Color::CyanLight),
            filler(),
            text(fmtBytesRate(s.bytes_per_sec) + "  ") | color(Color::GreenLight),
            text(fmtPkts(static_cast<std::uint64_t>(s.packets_per_sec)) + " pps  ")
                | color(Color::Yellow),
            text("● live") | blink | color(Color::GreenLight),
            text("  [Q] quit  [iface: " + config_.interface_name + "] "),
            text(std::string(time_buf) + " ") | bold | color(Color::White),
        }) | bgcolor(Color::NavyBlue);

        // Stat counters — equal-width single-line cards ----------------------
        auto statCell = [](const std::string& label, const std::string& val,
                           const std::string& sub, Color col) {
            return hbox({
                text(label + " ") | color(Color::GrayLight) | bold,
                text(val) | color(col) | bold,
                text(" (" + sub + ")") | color(Color::GrayLight),
            }) | border | flex;
        };
        auto counters = hbox({
            statCell("PKT",    fmtPkts(s.total_packets),
                fmtPkts(static_cast<std::uint64_t>(s.packets_per_sec)) + "/s",
                Color::CyanLight),
            statCell("BYTES",  fmtBytes(s.total_bytes),
                fmtBytesRate(s.bytes_per_sec),
                Color::BlueLight),
            statCell("FLOWS",  std::to_string(s.active_flows),
                "active",
                Color::GreenLight),
            statCell("TCP",    fmtPkts(s.tcp_packets),
                "pkts",
                Color::Cyan),
            statCell("UDP",    fmtPkts(s.udp_packets),
                "pkts",
                Color::Yellow),
            statCell("ALERTS", std::to_string(s.alerts.size()),
                s.alerts.empty() ? "✓ clean" : "⚑ active",
                s.alerts.empty() ? Color::GreenLight : Color::Red),
        });

        // Main content switcher
        Element main_content;
        if (tab_selected == 0) {
            main_content = overviewPanel(s, bw_history, pps_history) | flex;
        } else if (tab_selected == 1) {
            main_content = flowsPanel(s, 100, &flows_scroll_y) | flex;
        } else if (tab_selected == 2) {
            // Dedicated Alerts tab — full-size alertsMiniPanel
            main_content = alertsMiniPanel(s) | flex;
        } else if (tab_selected == 3) {
            main_content = dnsLogPanel(s) | flex;
        } else if (tab_selected == 4) {
            main_content = protocolsPanel(s) | flex;
        } else if (tab_selected == 5) {
            main_content = endpointsPanel(s) | flex;
        } else if (tab_selected == 6) {
            main_content = trafficGraphPanel(long_bw_history, long_pps_history);
        } else if (tab_selected == 7) {
            main_content = analyticsPanel(s) | flex;
        } else if (tab_selected == 8) {
            main_content = firewallPanel(s) | flex;
        } else if (tab_selected == 9) {
            main_content = ipsPanel(s) | flex;
        } else if (tab_selected == 10) {
            main_content = idsPanel(s) | flex;
        } else if (tab_selected == 11) {
            main_content = cryptoPanel(s) | flex;
        } else if (tab_selected == 12) {
            main_content = helpPanel() | flex;
        }

        // Modern custom pill tab bar ----------------------------------------
        Elements tab_pills;
        tab_pills.push_back(text(" "));
        for (int i = 0; i < (int)tab_entries.size(); ++i) {
            bool active = (i == tab_selected);
            Element pill = text(" " + tab_entries[i] + " ");
            if (active) {
                pill = pill | bold | color(Color::Black) | bgcolor(Color::GreenLight);
            } else {
                pill = pill | color(Color::GrayLight);
            }
            tab_pills.push_back(pill);
            tab_pills.push_back(text(" "));
        }
        tab_pills.push_back(filler());
        tab_pills.push_back(text(" [ ← / → Navigate ] ") | bold | color(Color::GrayLight));
        auto tabbar = hbox(std::move(tab_pills));

        // Full layout -------------------------------------------------------
        return vbox({
            header,
            counters,
            tabbar,
            separatorDouble(),
            main_content,
        });
    });

    // Catch keyboard events -------------------------------------------------
    std::size_t last_alert_count = 0;
    auto component = CatchEvent(renderer, [&](Event event) {
        // Bell on new HIGH severity alert
        const StatsSnapshot snap = statistics_.snapshot();
        if (snap.alerts.size() > last_alert_count) {
            const Alert& newest = snap.alerts.back();
            if (newest.severity == Severity::HIGH) {
                std::cout << '\a' << std::flush; // terminal bell
            }
            last_alert_count = snap.alerts.size();
        }
        if (event == Event::Character('q') || event == Event::Character('Q') ||
            event == Event::Escape) {
            running.store(false);
            screen.ExitLoopClosure()();
            return true;
        }
        if (tab_selected == 1) {
            if (event == Event::ArrowUp || event == Event::Character('k')) {
                flows_scroll_y++;
                return true;
            }
            if (event == Event::ArrowDown || event == Event::Character('j')) {
                flows_scroll_y--;
                return true;
            }
        }
        return false;
    });

    // Background refresh thread — fires an Event::Custom at refresh_ms rate --
    std::thread refresher([&] {
        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.refresh_ms));
            screen.PostEvent(Event::Custom);
        }
    });

    screen.Loop(component);

    running.store(false);
    if (refresher.joinable()) refresher.join();
}

#else // -----------------------------------------------------------------------
// Plain-terminal fallback (no FTXUI)
// -----------------------------------------------------------------------

Dashboard::Dashboard(const Config& config, const SharedStatistics& statistics)
    : config_(config), statistics_(statistics) {}

void Dashboard::run(std::atomic<bool>& running) {
    while (running.load()) {
        const StatsSnapshot snapshot = statistics_.snapshot();
        drawPlain(snapshot);
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.refresh_ms));
    }
}

#endif // PACMAN_HAVE_FTXUI

// ============================================================================
// Plain terminal draw (shared between the non-FTXUI path and FTXUI-absent builds)
// ============================================================================

void Dashboard::drawPlain(const StatsSnapshot& snapshot) const {
    // ANSI clear + home
    std::cout << "\033[2J\033[H";
    std::cout << "=== PacMan - Packet Analysis & Cyber Monitoring ===\n";
    std::cout << "Packets: " << fallback_fmtPkts(snapshot.total_packets)
              << "  Bytes: "  << fallback_fmtBytes(snapshot.total_bytes)
              << "  Rate: "   << fallback_fmtBytesRate(snapshot.bytes_per_sec)
              << "  Flows: "  << snapshot.active_flows
              << "  TCP: "    << fallback_fmtPkts(snapshot.tcp_packets)
              << "  UDP: "    << fallback_fmtPkts(snapshot.udp_packets)
              << "  Alerts: " << snapshot.alerts.size() << "\n\n";

    std::cout << "Traffic Breakdown:\n";
    for (const std::pair<const std::string, std::uint64_t>& entry : snapshot.traffic_by_class) {
        std::cout << "  " << entry.first << ": " << fallback_fmtBytes(entry.second) << "\n";
    }

    std::cout << "\nTop Domains:\n";
    std::vector<std::pair<std::string, std::uint64_t>> domains(
        snapshot.top_domains.begin(), snapshot.top_domains.end());
    std::sort(domains.begin(), domains.end(),
              [](const std::pair<std::string, std::uint64_t>& a, const std::pair<std::string, std::uint64_t>& b){ return a.second > b.second; });
    const std::size_t dlimit = std::min<std::size_t>(domains.size(), 8);
    for (std::size_t i = 0; i < dlimit; ++i)
        std::cout << "  " << domains[i].first << " (" << domains[i].second << " pkts)\n";

    std::cout << "\nTop Talkers:\n";
    std::vector<std::pair<std::string, std::uint64_t>> talkers(
        snapshot.top_talkers.begin(), snapshot.top_talkers.end());
    std::sort(talkers.begin(), talkers.end(),
              [](const std::pair<std::string, std::uint64_t>& a, const std::pair<std::string, std::uint64_t>& b){ return a.second > b.second; });
    const std::size_t tlimit = std::min<std::size_t>(talkers.size(), 5);
    for (std::size_t i = 0; i < tlimit; ++i)
        std::cout << "  " << talkers[i].first << " -> " << fallback_fmtBytes(talkers[i].second) << "\n";

    std::cout << "\nRecent Alerts:\n";
    if (snapshot.alerts.empty()) {
        std::cout << "  (none)\n";
    }
    for (const Alert& alert : snapshot.alerts) {
        const std::string domain = alert.hostname.empty() ? "—" : alert.hostname;
        std::cout << "  [" << severityToString(alert.severity) << "] "
                  << alert.source_ip << " | domain: " << domain
                  << " | " << alert.description << "\n";
    }
}

} // namespace PacMan
